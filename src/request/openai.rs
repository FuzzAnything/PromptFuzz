use std::{process::Child, time::Duration};

use crate::{
    config::{self, get_config, get_openai_proxy},
    is_critical_err,
    program::Program,
    FuzzerError,
};
use async_openai::{
    config::OpenAIConfig, types::{
        ChatCompletionRequestMessage, CreateChatCompletionRequest, CreateChatCompletionRequestArgs, CreateChatCompletionResponse
    }, Client
};
use eyre::Result;
use once_cell::sync::OnceCell;
use futures::future::join_all;


use super::Handler;

/// Token使用统计结构
#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

impl TokenUsage {
    pub fn new(prompt_tokens: u32, completion_tokens: u32, total_tokens: u32) -> Self {
        Self {
            prompt_tokens,
            completion_tokens,
            total_tokens,
        }
    }
    
    pub fn from_response(response: &CreateChatCompletionResponse) -> Self {
        if let Some(usage) = &response.usage {
            Self {
                prompt_tokens: usage.prompt_tokens,
                completion_tokens: usage.completion_tokens,
                total_tokens: usage.total_tokens,
            }
        } else {
            Self::default()
        }
    }
    
    pub fn add(&mut self, other: &TokenUsage) {
        self.prompt_tokens += other.prompt_tokens;
        self.completion_tokens += other.completion_tokens;
        self.total_tokens += other.total_tokens;
    }
}

pub struct OpenAIHanler {
    _child: Option<Child>,
    rt: tokio::runtime::Runtime,
}

impl Default for OpenAIHanler {
    fn default() -> Self {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| panic!("Unable to build the openai runtime."));
        Self { _child: None, rt }
    }
}

impl Handler for OpenAIHanler {
    /// Generate `SAMPLE_N` programs by chatting with instructions.
    fn generate(&self, prompt: &super::prompt::Prompt) -> eyre::Result<Vec<Program>> {
        let start = std::time::Instant::now();
        let chat_msgs = prompt.to_chatgpt_message();
        let mut futures = Vec::new();
        for _ in 0..get_config().n_sample {
            let future = generate_program_by_chat(chat_msgs.clone());
            futures.push(future);
        }
        let results = self.rt.block_on(join_all(futures));
        
        let mut programs = Vec::new();
        let mut total_usage = TokenUsage::default();
        
        for result in results {
            let (program, usage) = result?;
            programs.push(program);
            total_usage.add(&usage);
        }
        
        let elapsed = start.elapsed();
        log::info!("OpenAI Generate time: {}s", elapsed.as_secs());
        log::info!("OpenAI Token Usage - Prompt: {}, Completion: {}, Total: {}", 
                  total_usage.prompt_tokens, 
                  total_usage.completion_tokens, 
                  total_usage.total_tokens);
        
        Ok(programs)
    }
}

/// Get the OpenAI interface client.
fn get_client() -> Result<&'static Client<OpenAIConfig>> {
    // read OpenAI API key form the env var (OPENAI_API_KEY).
    pub static CLIENT: OnceCell<Client<OpenAIConfig>> = OnceCell::new();
    let client = CLIENT.get_or_init(|| {
        let http_client = reqwest::ClientBuilder::new()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(180))
            .build()
            .unwrap();
        let openai_config = if let Some(proxy) = get_openai_proxy() {
            OpenAIConfig::default().with_api_base(proxy)
        } else {
            OpenAIConfig::new()
        };
        let client = Client::with_config(openai_config);
        
        client.with_http_client(http_client)
    });
    Ok(client)
}

/// Create a request for a chat prompt
fn create_chat_request(
    msgs: Vec<ChatCompletionRequestMessage>,
    stop: Option<String>,
) -> Result<CreateChatCompletionRequest> {
    let mut binding = CreateChatCompletionRequestArgs::default();
    let binding = binding.model(config::get_openai_model_name());

    let mut request = binding
        .messages(msgs)
        .temperature(config::get_config().temperature);
    if let Some(stop) = stop {
        request = request.stop(stop);
    }
    let request = request.build()?;
    Ok(request)
}

/// Get a response for a chat request
async fn get_chat_response(
    request: CreateChatCompletionRequest,
) -> Result<CreateChatCompletionResponse> {
    let client = get_client().unwrap();
    for _retry in 0..config::RETRY_N {
        let response = client
            .chat()
            .create(request.clone())
            .await
            .map_err(eyre::Report::new);
        match is_critical_err(&response) {
            crate::Critical::Normal => {
                let response = response?;
                return Ok(response);
            }
            crate::Critical::NonCritical => {
                continue;
            }
            crate::Critical::Critical => return Err(response.err().unwrap()),
        }
    }
    Err(FuzzerError::RetryError(format!("{request:?}"), config::RETRY_N).into())
}

pub async fn generate_program_by_chat(
    chat_msgs: Vec<ChatCompletionRequestMessage>,
) -> Result<(Program, TokenUsage)> {
    let request = create_chat_request(chat_msgs, None)?;
    let respond = get_chat_response(request).await?;
    
    let usage = TokenUsage::from_response(&respond);
    let choice = respond.choices.first().unwrap();
    let content = choice.message.content.as_ref().unwrap();
    let content = strip_code_wrapper(content);
    let program = Program::new(&content);
    Ok((program, usage))
}


fn strip_code_prefix<'a>(input: &'a str, pat: &str) -> &'a str {
    let pat = String::from_iter(["```", pat]);
    if input.starts_with(&pat) {
        if let Some(p) = input.strip_prefix(&pat) {
            return p;
        }
    }
    input
}

/// strip the code wrapper that ChatGPT generated with code.
fn strip_code_wrapper(input: &str) -> String {
    let mut input = input.trim();
    let mut event = "";
    if let Some(idx) = input.find("```") {
        event = &input[..idx];
        input = &input[idx..];
    }
    let input = strip_code_prefix(input, "cpp");
    let input = strip_code_prefix(input, "CPP");
    let input = strip_code_prefix(input, "C++");
    let input = strip_code_prefix(input, "c++");
    let input = strip_code_prefix(input, "c");
    let input = strip_code_prefix(input, "C");
    let input = strip_code_prefix(input, "\n");
    if let Some(idx) = input.rfind("```") {
        let input = &input[..idx];
        let input = ["/*", event, "*/\n", input].concat();
        return input;
    }
    ["/*", event, "*/\n", input].concat()
}

#[cfg(test)]
mod tests {
    use async_openai::types::{ChatCompletionRequestSystemMessageArgs, ChatCompletionRequestUserMessageArgs};

    use super::*;

    #[test]
    fn test_get_client() -> Result<()> {
        dotenv::dotenv().ok();
        config::init_openai_env();
        
        let client = get_client().unwrap();
        
        let messages: Vec<ChatCompletionRequestMessage> = vec![
            ChatCompletionRequestSystemMessageArgs::default()
            .content("You are a helpful assistant.")
            .build()?.into(),
            ChatCompletionRequestUserMessageArgs::default()
            .content("Explain Rust's ownership system in simple terms.")
            .build()?.into()
        ];

        // 创建请求
        let request = CreateChatCompletionRequestArgs::default()
            .model("claude_sonnet4")  // 使用Claude 2模型
            .messages(messages)
            .stream(false)
            .build()?;
        
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| panic!("Unable to build the openai runtime."));
        // 发送请求
        let response = rt.block_on(client.chat().create(request));
        
        // 处理响应
        match response {
            Ok(response) => {
                if let Some(choice) = response.choices.first() {
                    if let Some(con) = &choice.message.content {
                        println!("Response: {}", con);
                    }
                }
            }
            Err(e) => {
                eprintln!("API call failed: {:#?}", e);                // 不要panic，让测试继续
                return Err(e.into());
            }
        }
        Ok(())
    }
}
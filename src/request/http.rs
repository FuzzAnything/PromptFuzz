use std::time::Duration;
use std::collections::HashMap;
use reqwest::{Client, Method, Response, Error as ReqwestError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use eyre::{Result, eyre};
use tokio::time::timeout;
use async_openai::types::ChatCompletionRequestMessage;
use futures::future::join_all;

use crate::program::Program;

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
    
    pub fn from_openai_usage(usage: &OpenAIUsage) -> Self {
        Self {
            prompt_tokens: usage.prompt_tokens,
            completion_tokens: usage.completion_tokens,
            total_tokens: usage.total_tokens,
        }
    }
    
    pub fn add(&mut self, other: &TokenUsage) {
        self.prompt_tokens += other.prompt_tokens;
        self.completion_tokens += other.completion_tokens;
        self.total_tokens += other.total_tokens;
    }
}

/// HTTP客户端配置
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    pub base_url: String,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub default_headers: HashMap<String, String>,
    pub retry_attempts: u32,
    pub retry_delay: Duration,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("User-Agent".to_string(), "PromptFuzz-HTTP-Client/1.0".to_string());
        
        Self {
            base_url: "https://api.openai.com".to_string(),
            timeout: Duration::from_secs(180),
            connect_timeout: Duration::from_secs(10),
            default_headers: headers,
            retry_attempts: 3,
            retry_delay: Duration::from_secs(2),
        }
    }
}

impl HttpClientConfig {
    pub fn set_base_url(&mut self, base_url: &str) {
        self.base_url = base_url.to_string();
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
}

/// OpenAI API请求结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIRequest {
    pub model: String,
    pub messages: Vec<OpenAIMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
}

/// OpenAI消息结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIMessage {
    pub role: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
}

/// OpenAI API响应结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIResponse {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub model: String,
    pub choices: Vec<OpenAIChoice>,
    pub usage: OpenAIUsage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_fingerprint: Option<String>,
}

/// OpenAI选择结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIChoice {
    #[serde(default)]
    pub index: u32,
    pub message: OpenAIMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logprobs: Option<Value>,
}

/// OpenAI使用情况结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
    #[serde(default)]
    pub cache_creation_input_tokens: u32,
    #[serde(default)]
    pub cache_read_input_tokens: u32,
}

/// HTTP客户端错误类型
#[derive(Debug, thiserror::Error)]
pub enum HttpClientError {
    #[error("Request failed: {0}")]
    RequestError(#[from] ReqwestError),
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("API error: {status} - {message}")]
    ApiError { status: u16, message: String },
    #[error("Retry exhausted after {attempts} attempts")]
    RetryExhausted { attempts: u32 },
}

/// HTTP客户端实现
pub struct HttpClient {
    client: Client,
    config: HttpClientConfig,
}

impl HttpClient {
    /// 创建新的HTTP客户端实例
    pub fn new(config: HttpClientConfig) -> Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        
        // 添加默认头部
        for (key, value) in &config.default_headers {
            let header_name: reqwest::header::HeaderName = key.parse()?;
            let header_value: reqwest::header::HeaderValue = value.parse()?;
            headers.insert(header_name, header_value);
        }
        
        let client = Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .default_headers(headers)
            .build()?;
        
        Ok(Self { client, config })
    }
    
    /// 使用默认配置创建客户端
    pub fn with_default_config() -> Result<Self> {
        Self::new(HttpClientConfig::default())
    }
    
    /// 设置API密钥
    pub fn with_api_key(mut self, api_key: &str) -> Self {
        self.config.default_headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", api_key),
        );
        self
    }
    
    /// 设置自定义基础URL
    pub fn with_base_url(mut self, base_url: &str) -> Self {
        self.config.base_url = base_url.to_string();
        self
    }
    
    /// 发送OpenAI聊天完成请求
    pub async fn chat_completion(&self, request: &OpenAIRequest) -> Result<OpenAIResponse> {
        let url = format!("{}/chat/completions", self.config.base_url);
        
        let response = self.send_request_with_retry(
            Method::POST,
            &url,
            Some(request),
            Some(self.config.default_headers.clone()),
        ).await?;
        
        self.parse_openai_response(response).await
    }
    
    /// 发送通用HTTP请求
    pub async fn send_request<T: Serialize>(
        &self,
        method: Method,
        url: &str,
        body: Option<&T>,
        headers: Option<HashMap<String, String>>,
    ) -> Result<Response> {
        let mut request_builder = self.client.request(method, url);
        
        // 添加自定义头部
        if let Some(headers) = headers {
            for (key, value) in headers {
                request_builder = request_builder.header(key, value);
            }
        }
        
        // 添加请求体
        if let Some(body) = body {
            request_builder = request_builder.json(body);
        }
        
        let response = request_builder.send().await?;
        
        if !response.status().is_success() {
            return Err(HttpClientError::ApiError {
                status: response.status().as_u16(),
                message: response.text().await.unwrap_or_else(|_| "Unknown error".to_string()),
            }.into());
        }
        
        Ok(response)
    }
    
    /// 带重试机制的请求发送
    async fn send_request_with_retry<T: Serialize>(
        &self,
        method: Method,
        url: &str,
        body: Option<&T>,
        headers: Option<HashMap<String, String>>,
    ) -> Result<Response> {
        let mut last_error = None;
        
        for attempt in 0..self.config.retry_attempts {
            match timeout(
                self.config.timeout,
                self.send_request(method.clone(), url, body, headers.clone())
            ).await {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(e)) => {
                    last_error = Some(e);
                    log::warn!("Request attempt {} failed: {:?}", attempt + 1, last_error);
                    
                    if attempt < self.config.retry_attempts - 1 {
                        tokio::time::sleep(self.config.retry_delay).await;
                    }
                }
                Err(_) => {
                    let timeout_error = HttpClientError::TimeoutError(
                        format!("Request to {} timed out after {:?}", url, self.config.timeout)
                    );
                    last_error = Some(timeout_error.into());
                    
                    if attempt < self.config.retry_attempts - 1 {
                        tokio::time::sleep(self.config.retry_delay).await;
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| {
            HttpClientError::RetryExhausted {
                attempts: self.config.retry_attempts,
            }.into()
        }))
    }
    
    /// 解析OpenAI API响应
    async fn parse_openai_response(&self, response: Response) -> Result<OpenAIResponse> {
        let text = response.text().await?;
        
        // 首先尝试解析为成功响应
        match serde_json::from_str::<OpenAIResponse>(&text) {
            Ok(openai_response) => Ok(openai_response),
            Err(parse_error) => {
                log::debug!("Failed to parse OpenAI response: {}", parse_error);
                log::debug!("Response text: {}", text);
                
                // 如果失败，尝试解析为错误响应
                let error_value: Value = serde_json::from_str(&text)
                    .map_err(|e| HttpClientError::ParseError(format!("Failed to parse JSON: {} | Response: {}", e, text)))?;
                
                if let Some(error_obj) = error_value.get("error") {
                    let error_message = error_obj.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Unknown error");
                    
                    return Err(eyre!("OpenAI API error: {}", error_message));
                }
                
                // 如果不是错误响应，可能是格式略有不同的成功响应
                // 尝试手动构建OpenAIResponse
                if let Some(choices) = error_value.get("choices") {
                    let default_usage = serde_json::json!({});
                    let usage = error_value.get("usage").unwrap_or(&default_usage);
                    
                    let openai_response = OpenAIResponse {
                        id: error_value.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        object: error_value.get("object").and_then(|v| v.as_str()).unwrap_or("chat.completion").to_string(),
                        created: error_value.get("created").and_then(|v| v.as_u64()).unwrap_or(0),
                        model: error_value.get("model").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        choices: serde_json::from_value(choices.clone())
                            .map_err(|e| HttpClientError::ParseError(format!("Failed to parse choices: {}", e)))?,
                        usage: serde_json::from_value(usage.clone())
                            .map_err(|e| HttpClientError::ParseError(format!("Failed to parse usage: {}", e)))?,
                        system_fingerprint: error_value.get("system_fingerprint").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    };
                    
                    return Ok(openai_response);
                }
                
                Err(HttpClientError::ParseError(format!("Unexpected response format: {} | Parse error: {}", text, parse_error)).into())
            }
        }
    }
    
    /// 解析任意JSON响应
    pub async fn parse_json_response<T: for<'de> Deserialize<'de>>(
        &self,
        response: Response,
    ) -> Result<T> {
        let text = response.text().await?;
        serde_json::from_str(&text)
            .map_err(|e| HttpClientError::ParseError(format!("Failed to parse JSON: {}", e)).into())
    }
    
    /// 获取响应文本
    pub async fn get_response_text(&self, response: Response) -> Result<String> {
        response.text().await
            .map_err(|e| HttpClientError::RequestError(e).into())
    }
    
    /// 验证OpenAI请求格式
    pub fn validate_openai_request(&self, request: &OpenAIRequest) -> Result<()> {
        if request.model.is_empty() {
            return Err(eyre!("Model cannot be empty"));
        }
        
        if request.messages.is_empty() {
            return Err(eyre!("Messages cannot be empty"));
        }
        
        for message in &request.messages {
            if !["system", "user", "assistant"].contains(&message.role.as_str()) {
                return Err(eyre!("Invalid message role: {}", message.role));
            }
            
            if message.content.is_empty() {
                return Err(eyre!("Message content cannot be empty"));
            }
        }
        
        Ok(())
    }
    
    /// 构建OpenAI请求
    pub fn build_openai_request(
        model: &str,
        messages: Vec<OpenAIMessage>,
        temperature: Option<f32>,
        max_tokens: Option<u32>,
    ) -> OpenAIRequest {
        OpenAIRequest {
            model: model.to_string(),
            messages,
            temperature,
            max_tokens,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            stop: None,
            stream: Some(false),
        }
    }
    
    /// 将async_openai的消息转换为我们的消息格式
    pub fn convert_chat_message(message: &ChatCompletionRequestMessage) -> OpenAIMessage {
        let (role, content) = match message {
            ChatCompletionRequestMessage::System(msg) => {
                let content_str = match &msg.content {
                    async_openai::types::ChatCompletionRequestSystemMessageContent::Text(text) => text.clone(),
                    async_openai::types::ChatCompletionRequestSystemMessageContent::Array(_) => {
                        // 简化处理：将数组转换为文本
                        "System message with array content".to_string()
                    }
                };
                ("system".to_string(), content_str)
            }
            ChatCompletionRequestMessage::User(msg) => {
                let content_str = match &msg.content {
                    async_openai::types::ChatCompletionRequestUserMessageContent::Text(text) => text.clone(),
                    async_openai::types::ChatCompletionRequestUserMessageContent::Array(_) => {
                        // 简化处理：将数组转换为文本
                        "User message with array content".to_string()
                    }
                };
                ("user".to_string(), content_str)
            }
            ChatCompletionRequestMessage::Assistant(msg) => {
                let content_str = match &msg.content {
                    Some(content) => match content {
                        async_openai::types::ChatCompletionRequestAssistantMessageContent::Text(text) => text.clone(),
                        async_openai::types::ChatCompletionRequestAssistantMessageContent::Array(_) => {
                            // 简化处理：将数组转换为文本
                            "Assistant message with array content".to_string()
                        }
                    },
                    None => "".to_string(),
                };
                ("assistant".to_string(), content_str)
            }
            ChatCompletionRequestMessage::Tool(msg) => {
                let content_str = match &msg.content {
                    async_openai::types::ChatCompletionRequestToolMessageContent::Text(text) => text.clone(),
                    async_openai::types::ChatCompletionRequestToolMessageContent::Array(_) => {
                        // 简化处理：将数组转换为文本
                        "Tool message with array content".to_string()
                    }
                };
                ("tool".to_string(), content_str)
            }
            ChatCompletionRequestMessage::Function(msg) => {
                ("function".to_string(), msg.content.clone().unwrap_or_else(|| "".to_string()))
            }
            ChatCompletionRequestMessage::Developer(msg) => {
                let content_str = match &msg.content {
                    async_openai::types::ChatCompletionRequestDeveloperMessageContent::Text(text) => text.clone(),
                    async_openai::types::ChatCompletionRequestDeveloperMessageContent::Array(_) => {
                        // 简化处理：将数组转换为文本
                        "Developer message with array content".to_string()
                    }
                };
                ("developer".to_string(), content_str)
            }
        };
        
        OpenAIMessage {
            role,
            content,
            name: None,
        }
    }
}

/// OpenAI消息构建器
pub struct OpenAIMessageBuilder;

impl OpenAIMessageBuilder {
    /// 创建系统消息
    pub fn system(content: &str) -> OpenAIMessage {
        OpenAIMessage {
            role: "system".to_string(),
            content: content.to_string(),
            name: None,
        }
    }
    
    /// 创建用户消息
    pub fn user(content: &str) -> OpenAIMessage {
        OpenAIMessage {
            role: "user".to_string(),
            content: content.to_string(),
            name: None,
        }
    }
    
    /// 创建助手消息
    pub fn assistant(content: &str) -> OpenAIMessage {
        OpenAIMessage {
            role: "assistant".to_string(),
            content: content.to_string(),
            name: None,
        }
    }
    
    /// 创建带名称的消息
    pub fn with_name(mut message: OpenAIMessage, name: &str) -> OpenAIMessage {
        message.name = Some(name.to_string());
        message
    }
}

/// 基于HTTP客户端的Handler实现
/// 这个实现展示了如何使用HTTP客户端来处理OpenAI请求
pub struct HttpHandler {
    client: HttpClient,
    rt: tokio::runtime::Runtime,
}

impl HttpHandler {
    /// 创建新的HttpHandler实例
    pub fn new() -> Result<Self> {
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| eyre!("OPENAI_API_KEY environment variable not set"))?;
        let base_url = crate::config::get_openai_proxy().clone().unwrap_or_else(|| "https://api.openai.com/v1".to_string());
        
        let client = HttpClient::with_default_config()?
            .with_api_key(&api_key)
            .with_base_url(&base_url);
        
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| eyre!("Failed to create tokio runtime: {}", e))?;
        
        Ok(Self { client, rt })
    }
    
    /// 使用自定义配置创建HttpHandler
    pub fn with_config(config: HttpClientConfig, api_key: &str) -> Result<Self> {
        let client = HttpClient::new(config)?.with_api_key(api_key);
        
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| eyre!("Failed to create tokio runtime: {}", e))?;
        
        Ok(Self { client, rt })
    }
    
    /// 异步生成单个程序
    async fn generate_single_program(&self, messages: Vec<OpenAIMessage>, model: String) -> Result<(Program, TokenUsage)> {
        let request = HttpClient::build_openai_request(
            &model,
            messages,
            Some(0.7),
            None,
        );
        
        let response = self.client.chat_completion(&request).await?;
        
        if response.choices.is_empty() {
            return Err(eyre!("No choices returned from OpenAI API"));
        }
        
        let content = &response.choices[0].message.content;
        let stripped_content = self.strip_code_wrapper(content);
        let usage = TokenUsage::from_openai_usage(&response.usage);
        
        Ok((Program::new(&stripped_content), usage))
    }
    
    /// 剥离代码包装器（复制自openai.rs）
    fn strip_code_wrapper(&self, input: &str) -> String {
        let mut input = input.trim();
        let mut event = "";
        if let Some(idx) = input.find("```") {
            event = &input[..idx];
            input = &input[idx..];
        }
        let input = self.strip_code_prefix(input, "cpp");
        let input = self.strip_code_prefix(input, "CPP");
        let input = self.strip_code_prefix(input, "C++");
        let input = self.strip_code_prefix(input, "c++");
        let input = self.strip_code_prefix(input, "c");
        let input = self.strip_code_prefix(input, "C");
        let input = self.strip_code_prefix(input, "\n");
        if let Some(idx) = input.rfind("```") {
            let input = &input[..idx];
            let input = ["/*", event, "*/\n", input].concat();
            return input;
        }
        ["/*", event, "*/\n", input].concat()
    }
    
    fn strip_code_prefix<'a>(&self, input: &'a str, pat: &str) -> &'a str {
        let pat = String::from_iter(["```", pat]);
        if input.starts_with(&pat) {
            if let Some(p) = input.strip_prefix(&pat) {
                return p;
            }
        }
        input
    }
}


impl super::Handler for HttpHandler {
    fn generate(&self, prompt: &super::prompt::Prompt) -> eyre::Result<Vec<Program>> {
        let start = std::time::Instant::now();
        
        // 将prompt转换为ChatGPT消息
        let chat_msgs = prompt.to_chatgpt_message();
        
        // 转换为我们的消息格式
        let messages: Vec<OpenAIMessage> = chat_msgs
            .iter()
            .map(HttpClient::convert_chat_message)
            .collect();
        
        // 获取配置
        let config = crate::config::get_config();
        let model = crate::config::get_openai_model_name().clone();
        
        // 创建异步任务，并行执行
        let mut futures = Vec::new();
        for _ in 0..config.n_sample {
            let messages_clone = messages.clone();
            let model_clone = model.clone();
            let future = self.generate_single_program(messages_clone, model_clone);
            futures.push(future);
        }
        
        // 并行执行所有任务
        let results = self.rt.block_on(join_all(futures));
        
        let mut programs = Vec::new();
        let mut total_usage = TokenUsage::default();
        
        for result in results {
            let (program, usage) = result?;
            programs.push(program);
            total_usage.add(&usage);
        }
        
        let elapsed = start.elapsed();
        log::info!("HTTP Client Generate time: {}s", elapsed.as_secs());
        log::info!("HTTP Client Token Usage - Prompt: {}, Completion: {}, Total: {}", 
                  total_usage.prompt_tokens, 
                  total_usage.completion_tokens, 
                  total_usage.total_tokens);
        
        Ok(programs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    
    #[tokio::test]
    async fn test_http_client_creation() {
        let config = HttpClientConfig::default();
        let client = HttpClient::new(config);
        assert!(client.is_ok());
    }
    
    #[tokio::test]
    async fn test_openai_request_validation() {
        let client = HttpClient::with_default_config().unwrap();
        
        // 有效请求
        let valid_request = OpenAIRequest {
            model: "gpt-3.5-turbo".to_string(),
            messages: vec![OpenAIMessageBuilder::user("Hello")],
            temperature: Some(0.7),
            max_tokens: Some(100),
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            stop: None,
            stream: Some(false),
        };
        
        assert!(client.validate_openai_request(&valid_request).is_ok());
        
        // 无效请求（空模型）
        let invalid_request = OpenAIRequest {
            model: "".to_string(),
            messages: vec![OpenAIMessageBuilder::user("Hello")],
            temperature: Some(0.7),
            max_tokens: Some(100),
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            stop: None,
            stream: Some(false),
        };
        
        assert!(client.validate_openai_request(&invalid_request).is_err());
    }
    
    #[tokio::test]
    async fn test_message_builder() {
        let system_msg = OpenAIMessageBuilder::system("You are a helpful assistant.");
        assert_eq!(system_msg.role, "system");
        assert_eq!(system_msg.content, "You are a helpful assistant.");
        
        let user_msg = OpenAIMessageBuilder::user("Hello");
        assert_eq!(user_msg.role, "user");
        assert_eq!(user_msg.content, "Hello");
        
        let assistant_msg = OpenAIMessageBuilder::assistant("Hi there!");
        assert_eq!(assistant_msg.role, "assistant");
        assert_eq!(assistant_msg.content, "Hi there!");
        
        let named_msg = OpenAIMessageBuilder::with_name(user_msg, "TestUser");
        assert_eq!(named_msg.name, Some("TestUser".to_string()));
    }
    
    #[tokio::test]
    async fn test_openai_chat_completion() {
        // 这个测试需要真实的API密钥，仅在环境变量设置时运行
         if let Ok(api_key) = env::var("OPENAI_API_KEY") {
            let client = HttpClient::with_default_config()
                .unwrap()
                .with_api_key(&api_key);
            
            let request = HttpClient::build_openai_request(
                "claude_sonnet4",
                vec![
                    OpenAIMessageBuilder::system("You are a helpful assistant."),
                    OpenAIMessageBuilder::user("Say hello in one word."),
                ],
                Some(0.7),
                Some(1024),
            );
            
            let response = client.chat_completion(&request).await;
            
            match response {
                Ok(response) => {
                    assert!(!response.choices.is_empty());
                    assert!(!response.choices[0].message.content.is_empty());
                    println!("Response: {}", response.choices[0].message.content);
                }
                Err(e) => {
                    println!("API call failed (expected if no API key): {}", e);
                }
            }
        }
    }
    
    #[test]
    fn test_http_handler_creation() {
        // 测试需要设置环境变量
        env::set_var("OPENAI_API_KEY", "test-key");
        env::set_var("OPENAI_MODEL_NAME", "gpt-3.5-turbo");
        
        // 初始化配置
        crate::config::init_openai_env();
        
        let handler = HttpHandler::new();
        assert!(handler.is_ok());
        
        env::remove_var("OPENAI_API_KEY");
        env::remove_var("OPENAI_MODEL_NAME");
    }
}

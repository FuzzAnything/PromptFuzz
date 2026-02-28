use crate::{
    config::{self, get_config, get_library_name},
    deopt::Deopt,
    execution::{
        logger::{init_gtl, ProgramLogger},
        Executor,
    },
    feedback::{
        observer::Observer,
        schedule::{rand_choose_combination, Schedule},
    },
    minimize::minimize,
    program::{libfuzzer::LibFuzzer, rand::rand_comb_len, serde::Deserializer, Program},
    request::{
        self,
        prompt::{load_prompt, Prompt},
    },
};
use eyre::Result;

pub struct Fuzzer {
    pub deopt: Deopt,
    pub executor: Executor,
    pub observer: Observer,
    schedule: Schedule,
    /// LLM model handler
    handler: Box<dyn request::Handler>,
    pub quiet_round: usize,
}

impl Fuzzer {
    /// create a new fuzzer
    pub fn new() -> Result<Self> {
        let deopt = Deopt::new(get_library_name())?;
        let executor = Executor::new(&deopt)?;
        let observer = Observer::new(&deopt);
        let handler: Box<dyn request::Handler> = Box::<request::openai::OpenAIHanler>::default();
        init_gtl();
        let fuzzer = Self {
            deopt,
            executor,
            observer,
            schedule: Schedule::new(),
            handler,
            quiet_round: 0,
        };
        Ok(fuzzer)
    }

    fn sync_quiet_round(&mut self, content: &str) -> Result<()> {
        if let Some(idx) = content.find("[Mutate Loop]: loop:") {
            let mut de = Deserializer::from_input(&content[idx..]);
            de.consume_token_until("quiet_round:")?;
            let quiet_round = de.parse_number::<usize>()?;
            self.quiet_round = quiet_round;
        }
        Ok(())
    }

    // When the execution stopped or crashed by internal's bugs, sync from the previous state.
    pub fn sync_from_previous_state(&mut self, logger: &mut ProgramLogger) -> Result<()> {
        let mut is_the_last = false;
        for file in crate::deopt::utils::read_sort_dir(&self.deopt.get_library_output_dir()?)?
            .iter()
            .rev()
        {
            if file.is_dir() {
                continue;
            }
            if let Some(ext) = file.extension() {
                if ext == "log" {
                    if !is_the_last {
                        is_the_last = true;
                        continue;
                    }
                    log::info!("Find a previous exection: {file:?}");
                    log::info!("Restore the states from the previous execution!");
                    let log_str = std::fs::read_to_string(file)?;
                    let sync_logger = ProgramLogger::snyc_from_str(&log_str)?;
                    self.deopt.seed_id = sync_logger.get_gc_total();
                    _ = std::mem::replace(logger, sync_logger);
                    let observer = Observer::sync_from_previous(&mut self.deopt)?;
                    _ = std::mem::replace(&mut self.observer, observer);
                    Schedule::snyc_from_str(&self.deopt);
                    self.sync_quiet_round(&log_str)?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    pub fn transform_seeds_to_fuzzers(&self) -> Result<()> {
        let programs = crate::deopt::utils::read_sort_dir(&self.deopt.get_library_seed_dir()?)?;
        let core = get_config().cores;
        let fuzzer_size = programs.len();
        let mut libfuzzer = LibFuzzer::new(
            programs.clone(),
            fuzzer_size,
            core,
            self.deopt.clone(),
            false,
        );
        libfuzzer.transform()?;
        libfuzzer.synthesis()?;
        libfuzzer.compile()?;
        let mut libfuzzer = LibFuzzer::new(programs, fuzzer_size, core, self.deopt.clone(), true);
        libfuzzer.transform()?;
        libfuzzer.synthesis()?;
        libfuzzer.compile()?;
        Ok(())
    }

    pub fn generate_until_n_success(
        &mut self,
        prompt: &mut Prompt,
        logger: &mut ProgramLogger,
    ) -> Result<Vec<Program>> {
        log::trace!(
            "Generate until {} sucess programs",
            get_config().fuzz_round_succ
        );
        let mut succ_programs = Vec::new();

        while succ_programs.len() < get_config().fuzz_round_succ {
            let mut programs = self.handler.generate(prompt)?;
            if programs.is_empty() {
                log::warn!("LLM did not generate any program, retrying...");
                continue;
            }
            for program in &mut programs {
                program.id = self.deopt.inc_seed_id();
            }

            log::debug!(
                "LLM generated {} programs. Sanitize those programs!",
                programs.len()
            );
            let check_res = self
                .executor
                .check_programs_are_correct(&programs, &self.deopt)?;
            // Check each generated programs, and save thems according where they contains errors.
            for (i, program) in programs.iter().enumerate() {
                let has_err = check_res
                    .get(i)
                    .unwrap_or_else(|| panic!("cannot obtain check_res at `{i}`"));
                // save as error programs
                if let Some(err_msg) = has_err {
                    self.deopt.save_err_program(program, err_msg)?;
                    logger.log_err(err_msg);
                } else {
                    succ_programs.push(program.clone());
                    logger.log_succ();
                }
            }
            logger.print_succ_round();
            // if the combiantion continusely failed in a long time, shuffle the prompt to escape the bad combination;
            if self
                .schedule
                .should_shuffle(logger.get_rc_succ(), logger.get_rc_total())
            {
                log::info!("Fuzzer stuck in the current prompt, choose a new one.");
                break;
            }
        }
        Ok(succ_programs)
    }

    fn mutate_prompt(&mut self, prompt: &mut Prompt) -> Result<()> {
        let api_coverage = self.observer.compute_library_api_coverage()?;
        self.schedule.update_energies(api_coverage);
        self.schedule.update_prompt(prompt, &mut self.deopt)?;
        Ok(())
    }

    pub fn is_converge(&self) -> bool {
        if get_config().fuzz_converge_round == 0 {
            return false;
        }
        if self.quiet_round >= get_config().fuzz_converge_round
        {
            return true;
        }
        false
    }

    pub fn is_stuck(&self, len: usize) -> bool {
        len == 0
    }

    pub fn should_recheck(&self) -> bool {
        if self.quiet_round >= get_config().fuzz_converge_round / 2 && get_config().recheck {
            return true;
        }
        false
    }

    pub fn fuzz_loop(&mut self) -> Result<()> {
        let mut logger = ProgramLogger::default();
        let initial_combination = rand_choose_combination(rand_comb_len());
        let mut prompt = if let Some(prompt) = load_prompt(&self.deopt) {
            prompt
        } else {
            Prompt::from_combination(initial_combination)
        };
        let mut loop_cnt = 0;
        let mut has_checked = false;

        self.sync_from_previous_state(&mut logger)?;

        loop {
            if self.is_converge() {
                break;
            }
            let programs = self.generate_until_n_success(&mut prompt, &mut logger)?;
            let is_stuck = self.is_stuck(programs.len());
            let mut has_new = false;
            for mut program in programs {
                self.deopt.save_succ_program(&program)?;
                let coverage = self.deopt.get_seed_coverage(program.id)?;
                let unique_branches = self.observer.has_unique_branch(&coverage);
                has_new = !unique_branches.is_empty();
                program.update_quality(unique_branches, &self.deopt)?;
                self.deopt.update_seed_queue(program, &coverage, has_new)?;
                self.observer.merge_coverage(&coverage);
            }
            if !get_config().disable_power_schedule {
                self.mutate_prompt(&mut prompt)?;
            } else {
                let new_comb = rand_choose_combination(config::DEFAULT_COMB_LEN);
                prompt = Prompt::from_combination(new_comb);
            }

            if has_new {
                self.quiet_round = 0;
            } else if !is_stuck {
                self.quiet_round += 1;
            }
            // As the corpus is also evolved, we recheck the seeds on the evolved corpus to eliminate the error programs that was not catched before.
            if self.should_recheck() && !has_checked {
                self.executor.recheck_seed(&mut self.deopt)?;
                self.observer.recompute_global_coverage()?;
                self.deopt.load_programs_from_seeds()?;
                has_checked = true;
                self.quiet_round = 0;
                crate::mutation::prompt_shuffle(&mut prompt);
            }
            loop_cnt += 1;
            logger.reset_round();
            log::info!(
                "[Mutate Loop]: loop: {loop_cnt}, quiet_round: {}, {}",
                self.quiet_round,
                self.observer.dump_global_states()
            );
        }
        log::info!("Global branch states converged!");
        minimize(&self.deopt)?;
        Ok(())
    }

    pub fn fuzzer_run(&self) -> Result<()> {
        self.transform_seeds_to_fuzzers()?;
        self.executor.run_libfuzzer(false, None, None)?;
        self.executor.run_libfuzzer(true, None, None)?;
        Ok(())
    }
}

impl Drop for Fuzzer {
    fn drop(&mut self) {
        log::info!("Config: {:#?}", get_config());
    }
}

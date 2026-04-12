use std::{collections::HashMap, f32::consts::E};

use crate::{
    deopt::Deopt,
    mutation::mutate_prompt,
    program::{
        gadget::{get_func_gadget, get_func_gadgets, FuncGadget},
        get_exec_counter_value, load_exec_counter,
        rand::{prob_coin, rand_comb_len, weighted_choose},
        set_exec_counter_value,
    },
    request::prompt::{
        get_prompt_counter_value, load_prompt_counter, set_prompt_counter_value, Prompt,
    },
};

pub struct Seed {
    name: String,
    coverage: f32,
    exec_count: u32,
    prompt_count: u32,
    energy: f32,
}

impl Seed {
    pub fn new(
        name: &str,
        coverage: f32,
        exec_count: u32,
        prompt_count: u32,
        exponent: u32,
    ) -> Self {
        let mut seed = Self {
            name: name.to_string(),
            coverage,
            exec_count,
            prompt_count,
            energy: 0_f32,
        };
        seed.compute_energy(exponent);
        seed
    }

    pub fn compute_energy(&mut self, exponent: u32) -> f32 {
        let top: f32 = 1_f32 - self.coverage;
        let count = 1 + self.exec_count;
        let round = 1 + self.prompt_count;
        let bottom: f32 = ((count * round).pow(exponent)) as f32;
        let energy = top / bottom;
        self.energy = energy;
        energy
    }
}

fn sigmoid_function(succ_rate: f32, threshold: f32, steepness: f32) -> f32 {
    let exponent = steepness * (threshold - succ_rate);
    1.0 / (1.0 + E.powf(exponent))
}

fn should_deterministic_mutate(deopt: &Deopt) -> bool {
    let seed_num = deopt.seed_queue.len();
    let prob = seed_num as f32 / 100.0_f32;
    let prob = prob.min(0.8_f32);
    let coin = prob_coin(prob);
    log::info!(
        "Number of current unique seeds: {}, prob: {prob}, coin: {coin}",
        deopt.seed_queue.len()
    );
    coin
}

pub struct Schedule {
    seeds: HashMap<String, Seed>,
    exponent: u32,
}

impl Default for Schedule {
    fn default() -> Self {
        Self::new()
    }
}

impl Schedule {
    pub fn new() -> Self {
        Self {
            seeds: HashMap::new(),
            exponent: 1,
        }
    }

    pub fn get_seed_by_name(&self, name: &str) -> Option<&Seed> {
        self.seeds.get(name)
    }

    pub fn snyc_from_str(deopt: &Deopt) {
        let p_counter = load_prompt_counter(deopt);
        let e_counter = load_exec_counter(deopt);
        for (key, value) in e_counter {
            set_exec_counter_value(key, value);
        }
        for (key, value) in p_counter {
            set_prompt_counter_value(key, value);
        }
    }

    // Compute the energy for each library API. The high energy means the high probablity to be choosed in prompt.
    pub fn update_energies(&mut self, api_coverage: &HashMap<String, f32>) {
        self.seeds.clear();
        for gadget in get_func_gadgets() {
            let api_name = gadget.get_func_name();
            let coverage = api_coverage.get(api_name).unwrap();
            let prompt_count = get_prompt_counter_value(api_name).unwrap_or(0);
            let exec_count = get_exec_counter_value(api_name).unwrap_or(0);
            let seed = Seed::new(api_name, *coverage, exec_count, prompt_count, self.exponent);
            self.seeds.insert(api_name.to_string(), seed);
        }
        let energies_str: Vec<f32> = self.seeds.values().map(|x| x.energy).collect();
        log::debug!(
            "energies: {}",
            serde_json::to_string(&energies_str).unwrap()
        );
    }

    pub fn update_prompt(&self, prompt: &mut Prompt, deopt: &mut Deopt) -> eyre::Result<()> {
        if should_deterministic_mutate(deopt) {
            mutate_prompt(prompt, self, deopt);
        } else {
            let combination = self.assemble_high_energy_combiantion();
            prompt.set_combination(combination);
        }
        Ok(())
    }

    pub fn should_delete(&self, succ_rate: f32) -> bool {
        let threshold = 0.1_f32;
        let steepness = 10_f32;
        let delete_prob = 1_f32 - sigmoid_function(succ_rate, threshold, steepness);
        prob_coin(delete_prob)
    }

    pub fn should_shuffle(&self, succ: usize, total: usize) -> bool {
        // we expect per 20 programs should have a succ one.
        if succ == 0 && total >= 30 {
            return true;
        }
        if succ == 0 && total < 30 {
            return false;
        }
        if succ * 30 < total {
            return true;
        }
        false
    }

    pub fn assemble_high_energy_combiantion(&self) -> Vec<&'static FuncGadget> {
        log::info!("random assemble new prompt combination with their engies.");
        let len = rand_comb_len();
        let mut comb: Vec<&str> = Vec::new();
        let mut gadgets = Vec::new();
        while comb.len() < len {
            let api = self.choose_api_by_energy();
            if comb.contains(&api) {
                continue;
            }
            comb.push(api);
            let gadget =
                get_func_gadget(api).unwrap_or_else(|| panic!("cannot found api {api} in gadgets"));
            gadgets.push(gadget);
        }
        gadgets
    }

    pub fn choose_api_by_energy(&self) -> &str {
        let values: Vec<&Seed> = self.seeds.values().collect();
        let energies: Vec<f32> = values.iter().map(|x| x.energy).collect();
        let choose = weighted_choose(energies);
        let choose_seed = values[choose];
        &choose_seed.name
    }

    pub fn choose_low_energy_api(&self, combination: &Vec<String>) -> usize {
        let mut energies: Vec<f32> = Vec::new();
        for api_name in combination {
            let energy = self
                .seeds
                .get(api_name)
                .unwrap_or_else(|| panic!("no seed named {api_name} in Schedule"))
                .energy;
            energies.push(energy);
        }
        weighted_choose(energies)
    }
}

pub fn rand_choose_combination(len: usize) -> Vec<&'static FuncGadget> {
    let mut combination: Vec<&'static FuncGadget> = Vec::new();
    let func_gagdets = get_func_gadgets();
    while combination.len() < len {
        let idx: usize = rand::random::<usize>() % func_gagdets.len();
        let gadget = &func_gagdets[idx];
        if combination
            .iter()
            .any(|x| x.get_func_name() == gadget.get_func_name())
        {
            continue;
        }
        combination.push(gadget);
    }
    combination
}

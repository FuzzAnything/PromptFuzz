use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Sancov {
    #[serde(rename = "covered-points")]
    pub covered_points: Vec<String>,
}
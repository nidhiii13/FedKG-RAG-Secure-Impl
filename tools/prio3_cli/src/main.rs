use std::io::{self, Read};

use prio::vdaf::prio3::Prio3;
use prio::vdaf::{Aggregator, Client, Collector, PrepareTransition};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Capabilities,
    SumVec {
        aggregator_count: u8,
        bits: usize,
        context: String,
        measurements: Vec<Vec<u64>>,
    },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Response {
    Capabilities {
        implementation: &'static str,
        operations: [&'static str; 1],
        min_aggregators: u8,
        local_reconstruction: bool,
    },
    SumVec {
        aggregate: Vec<String>,
        aggregator_count: u8,
        report_count: usize,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: Request = serde_json::from_str(&input)?;
    let response = match request {
        Request::Capabilities => Response::Capabilities {
            implementation: "libprio-rs/prio3",
            operations: ["sum_vec"],
            min_aggregators: 2,
            local_reconstruction: true,
        },
        Request::SumVec {
            aggregator_count,
            bits,
            context,
            measurements,
        } => run_sum_vec(aggregator_count, bits, context.as_bytes(), measurements)?,
    };
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

fn run_sum_vec(
    aggregator_count: u8,
    bits: usize,
    _context: &[u8],
    measurements: Vec<Vec<u64>>,
) -> Result<Response, Box<dyn std::error::Error>> {
    if aggregator_count < 2 {
        return Err("aggregator_count must be at least 2".into());
    }
    let width = measurements
        .first()
        .ok_or("at least one measurement is required")?
        .len();
    if width == 0 || measurements.iter().any(|measurement| measurement.len() != width) {
        return Err("measurement vectors must be non-empty and have equal length".into());
    }

    let encoded_length = bits
        .checked_mul(width)
        .ok_or("encoded measurement length overflow")?;
    let chunk_length = IntegerSquareRoot::isqrt(encoded_length).max(1);
    let vdaf = Prio3::new_sum_vec(aggregator_count, bits, width, chunk_length)?;
    let mut rng = thread_rng();
    let verify_key = rng.gen();
    let mut output_shares = vec![Vec::new(); usize::from(aggregator_count)];

    for measurement in &measurements {
        let measurement = measurement
            .iter()
            .copied()
            .map(u128::from)
            .collect::<Vec<_>>();
        let nonce = rng.gen::<[u8; 16]>();
        let (public_share, input_shares) = vdaf.shard(&measurement, &nonce)?;
        let mut states = Vec::with_capacity(input_shares.len());
        let mut prepare_shares = Vec::with_capacity(input_shares.len());
        for (aggregator_id, input_share) in input_shares.iter().enumerate() {
            let (state, prepare_share) = vdaf.prepare_init(
                &verify_key,
                aggregator_id,
                &(),
                &nonce,
                &public_share,
                input_share,
            )?;
            states.push(state);
            prepare_shares.push(prepare_share);
        }
        let message = vdaf.prepare_shares_to_prepare_message(&(), prepare_shares)?;
        for (aggregator_id, state) in states.into_iter().enumerate() {
            match vdaf.prepare_next(state, message.clone())? {
                PrepareTransition::Finish(output_share) => {
                    output_shares[aggregator_id].push(output_share)
                }
                PrepareTransition::Continue(..) => {
                    return Err("unexpected multi-round Prio3 preparation".into())
                }
            }
        }
    }

    let aggregate_shares = output_shares
        .into_iter()
        .map(|shares| vdaf.aggregate(&(), shares))
        .collect::<Result<Vec<_>, _>>()?;
    let aggregate = vdaf
        .unshard(&(), aggregate_shares, measurements.len())?
        .into_iter()
        .map(|value| value.to_string())
        .collect();
    Ok(Response::SumVec {
        aggregate,
        aggregator_count,
        report_count: measurements.len(),
    })
}

trait IntegerSquareRoot {
    fn isqrt(self) -> Self;
}

impl IntegerSquareRoot for usize {
    fn isqrt(self) -> Self {
        if self < 2 {
            return self;
        }
        let mut result = 1usize;
        while (result + 1).saturating_mul(result + 1) <= self {
            result += 1;
        }
        result
    }
}

/// Summary statistics of one timed phase, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    pub min: f64,
    pub median: f64,
    pub p95: f64,
    pub max: f64,
}

/// Summarise samples given in milliseconds. Returns `None` for an empty slice.
///
/// The median averages the two middle values for an even count. p95 uses the nearest-rank method:
/// the value at 1-based rank `ceil(0.95 * n)` of the sorted samples.
pub fn summarize(samples: &[f64]) -> Option<Summary> {
    if samples.is_empty() {
        return None;
    }

    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);

    let n = sorted.len();
    let median = if n % 2 == 1 {
        sorted[n / 2]
    } else {
        f64::midpoint(sorted[n / 2 - 1], sorted[n / 2])
    };

    let rank = (0.95 * n as f64).ceil() as usize;
    let p95 = sorted[rank.clamp(1, n) - 1];

    Some(Summary {
        min: sorted[0],
        median,
        p95,
        max: sorted[n - 1],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_no_summary() {
        assert_eq!(summarize(&[]), None);
    }

    #[test]
    fn single_sample_is_every_value() {
        let s = summarize(&[4.5]).unwrap();
        assert_eq!(
            s,
            Summary {
                min: 4.5,
                median: 4.5,
                p95: 4.5,
                max: 4.5
            }
        );
    }

    #[test]
    fn odd_count_median_is_middle_value() {
        let s = summarize(&[3.0, 1.0, 2.0]).unwrap();
        assert_eq!(s.median, 2.0);
        assert_eq!(s.min, 1.0);
        assert_eq!(s.max, 3.0);
    }

    #[test]
    fn even_count_median_averages_middle_pair() {
        let s = summarize(&[4.0, 1.0, 3.0, 2.0]).unwrap();
        assert_eq!(s.median, 2.5);
    }

    #[test]
    fn p95_nearest_rank_on_twenty_samples() {
        // ceil(0.95 * 20) = 19: the 19th smallest value.
        let samples: Vec<f64> = (1..=20).map(f64::from).collect();
        let s = summarize(&samples).unwrap();
        assert_eq!(s.p95, 19.0);
    }

    #[test]
    fn p95_nearest_rank_on_ten_samples_is_max() {
        // ceil(0.95 * 10) = 10: the largest value.
        let samples: Vec<f64> = (1..=10).map(f64::from).collect();
        assert_eq!(summarize(&samples).unwrap().p95, 10.0);
    }

    #[test]
    fn unsorted_input_with_duplicates() {
        let s = summarize(&[5.0, 5.0, 1.0, 5.0]).unwrap();
        assert_eq!(s.min, 1.0);
        assert_eq!(s.median, 5.0);
        assert_eq!(s.max, 5.0);
    }
}

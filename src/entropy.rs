//! Shannon entropy, used to reject low-randomness regex candidates.

/// Shannon entropy of `data` in bits per byte (0.0 for empty input, max 8.0).
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::shannon;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn empty_and_uniform() {
        assert!(approx(shannon(b""), 0.0));
        assert!(approx(shannon(b"aaaaaaaa"), 0.0));
    }

    #[test]
    fn known_values() {
        assert!(approx(shannon(b"ab"), 1.0));
        assert!(approx(shannon(b"abcd"), 2.0));
        assert!(approx(shannon(b"aabb"), 1.0));
        // 16 distinct symbols, each once: log2(16).
        assert!(approx(shannon(b"0123456789abcdef"), 4.0));
        let all: Vec<u8> = (0..=255).collect();
        assert!(approx(shannon(&all), 8.0));
    }

    #[test]
    fn random_looking_tokens_score_higher_than_words() {
        assert!(shannon(b"wJalrXUtnFEMIK7MDENGbPxRfiCY") > 4.0);
        assert!(shannon(b"passwordpassword") < 3.0);
    }
}

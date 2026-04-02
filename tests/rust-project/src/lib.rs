/// Simple math utilities for runner validation testing.

pub fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

pub fn lcm(a: u64, b: u64) -> u64 {
    if a == 0 || b == 0 {
        return 0;
    }
    a / gcd(a, b) * b
}

pub fn is_palindrome(s: &str) -> bool {
    let chars: Vec<char> = s.chars().filter(|c| c.is_alphanumeric()).collect();
    let lower: Vec<char> = chars.iter().map(|c| c.to_ascii_lowercase()).collect();
    let reversed: Vec<char> = lower.iter().rev().cloned().collect();
    lower == reversed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(12, 8), 4);
        assert_eq!(gcd(17, 13), 1);
        assert_eq!(gcd(100, 75), 25);
    }

    #[test]
    fn test_lcm() {
        assert_eq!(lcm(4, 6), 12);
        assert_eq!(lcm(0, 5), 0);
        assert_eq!(lcm(7, 3), 21);
    }

    #[test]
    fn test_palindrome() {
        assert!(is_palindrome("racecar"));
        assert!(is_palindrome("A man a plan a canal Panama"));
        assert!(!is_palindrome("hello"));
    }
}

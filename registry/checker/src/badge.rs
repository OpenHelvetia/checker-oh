//! Badge emission: one shields.io endpoint-schema JSON per entry.
//! The aggregation preserves the gradient — «never checked» and
//! «partially checked» are visible states, never rounded up to
//! green (E14 Ziff. 3).

use crate::gradient::Gradient;

/// Aggregated badge message + color for one entry's interfaces.
pub fn aggregate(gradients: &[Gradient]) -> (&'static str, &'static str) {
    let any_failed = gradients
        .iter()
        .any(|g| matches!(g, Gradient::Failed { .. }));
    let all_passed = !gradients.is_empty()
        && gradients
            .iter()
            .all(|g| matches!(g, Gradient::Passed { .. }));
    let any_passed = gradients
        .iter()
        .any(|g| matches!(g, Gradient::Passed { .. }));
    if any_failed {
        ("failed", "red")
    } else if all_passed {
        ("passed", "brightgreen")
    } else if any_passed {
        ("partially checked", "yellow")
    } else {
        ("never checked", "lightgrey")
    }
}

/// shields.io endpoint schema (schemaVersion 1).
pub fn shields_json(entry: &str, gradients: &[Gradient]) -> serde_json::Value {
    let (message, color) = aggregate(gradients);
    serde_json::json!({
        "schemaVersion": 1,
        "label": format!("oh-check {entry}"),
        "message": message,
        "color": color
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passed() -> Gradient {
        Gradient::Passed {
            measured_at: "2026-08-20T12:00:00Z".into(),
        }
    }
    fn failed() -> Gradient {
        Gradient::Failed {
            measured_at: "2026-08-20T12:00:00Z".into(),
        }
    }

    #[test]
    fn aggregation_preserves_the_gradient() {
        assert_eq!(aggregate(&[]).0, "never checked");
        assert_eq!(
            aggregate(&[Gradient::NeverChecked, Gradient::NeverChecked]).0,
            "never checked"
        );
        assert_eq!(
            aggregate(&[passed(), Gradient::NeverChecked]).0,
            "partially checked"
        );
        assert_eq!(aggregate(&[passed(), passed()]).0, "passed");
        // A failure dominates everything — never rounded away.
        assert_eq!(
            aggregate(&[passed(), failed(), Gradient::NeverChecked]).0,
            "failed"
        );
    }

    #[test]
    fn shields_schema_shape() {
        let value = shields_json("fedlex-sparql", &[passed()]);
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["message"], "passed");
        assert_eq!(value["color"], "brightgreen");
    }
}

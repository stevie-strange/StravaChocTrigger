"""Tests for the CHO / fat oxidation model (metabolic test, August 2026, issue #26).

The expected values are literals derived from the fitted model during planning.
They are deliberately not imported from the module so that an accidental edit of
the coefficients fails these tests.
"""
# pylint: disable=import-outside-toplevel,missing-function-docstring,import-error
import pytest

# Expected g/h at constant power. Columns: power (W), CHO (g/h), fat (g/h)
MODEL_VALUES = [
    (0, 23.243, 9.961),
    (50, 49.828, 9.188),
    (100, 83.409, 14.083),
    (125, 102.823, 16.696),
    (137.5, 113.186, 17.701),
    (150, 123.986, 18.375),
    (175, 146.898, 18.337),
    (200, 171.558, 15.797),
    (225, 197.968, 9.972),
    (250, 226.126, 0.078),
    (275, 256.034, 0.0),
    (300, 280.362, 0.0),
    (350, 319.439, 0.0),
    (400, 358.515, 0.0),
    (500, 436.669, 0.0),
]

# Measured stages from the spiroergometry report: power (W), CHO (g/h), fat (g/h)
REPORT_STAGES = [
    (125, 101.201, 18.044),
    (150, 127.302, 16.371),
    (175, 140.911, 17.825),
    (200, 161.568, 17.735),
    (225, 199.191, 9.321),
    (250, 244.943, 0.0),
    (275, 261.239, 0.0),
    (300, 275.491, 0.0),
]

ONE_HOUR = 3600


def _model():
    # Import lazily so the conftest shims for azure.* are in place
    from QueueTrigger1.__init__ import calc_cho, calculate_fat
    return calc_cho, calculate_fat


@pytest.mark.parametrize("power,cho,fat", MODEL_VALUES)
def test_model_values_at_constant_power(power, cho, fat):
    calc_cho, calculate_fat = _model()
    stream = [power] * ONE_HOUR
    assert calc_cho(stream) == pytest.approx(cho, abs=1e-3)
    assert calculate_fat(stream) == pytest.approx(fat, abs=1e-3)


@pytest.mark.parametrize("power,cho,fat", REPORT_STAGES)
def test_stage_fit_quality(power, cho, fat):
    calc_cho, calculate_fat = _model()
    stream = [power] * ONE_HOUR
    assert calc_cho(stream) == pytest.approx(cho, rel=0.12)
    assert calculate_fat(stream) == pytest.approx(fat, abs=3.0)


def test_energy_ceiling_active_above_290w():
    calc_cho, _ = _model()
    raw_quadratic_at_400w = 431.805
    result = calc_cho([400] * ONE_HOUR)
    assert result == pytest.approx(358.515, abs=1e-3)
    assert result < raw_quadratic_at_400w


@pytest.mark.parametrize("power", [275, 300, 400, 800])
def test_fat_zero_at_and_above_fatmin(power):
    _, calculate_fat = _model()
    assert calculate_fat([power] * ONE_HOUR) == 0.0


def test_reference_activity_totals():
    calc_cho, calculate_fat = _model()
    stream = ([125] * 600 + [200] * 600 + [137.5] * 600
              + [0] * 300 + [400] * 300 + [None] * 10)
    assert calc_cho(stream) == pytest.approx(96.4077, abs=1e-3)
    assert calculate_fat(stream) == pytest.approx(9.1958, abs=1e-3)


def test_negative_power_treated_as_zero():
    calc_cho, calculate_fat = _model()
    assert calc_cho([-5] * ONE_HOUR) == pytest.approx(23.243, abs=1e-3)
    assert calculate_fat([-5] * ONE_HOUR) == pytest.approx(9.961, abs=1e-3)


@pytest.mark.parametrize("stream", [[], [None, None]])
def test_empty_and_all_none_return_zero(stream):
    calc_cho, calculate_fat = _model()
    assert calc_cho(stream) == 0
    assert calculate_fat(stream) == 0

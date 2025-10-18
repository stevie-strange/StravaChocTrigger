# pylint: disable=missing-function-docstring,missing-module-docstring
import math
from QueueTrigger1.__init__ import build_description


def test_build_description_basic():
    total_cho = 100.4
    total_fat = 20.6
    activity_duration = 3600  # 1 hour

    desc = build_description(total_cho, total_fat, activity_duration)

    # Basic sanity checks
    assert 'Total carbohydrates burned' in desc
    assert 'Carbohydrates burned per hour' in desc
    assert 'Total fat burned' in desc
    assert 'Fat burned per hour' in desc

    # Numeric expectations: rounded values
    assert str(round(total_cho)) in desc
    assert str(round(total_fat)) in desc


def test_build_description_division():
    # Ensure activity_duration scaling is correct
    total_cho = 3600  # so per-hour value before scaling equals 1 per second
    total_fat = 7200
    activity_duration = 7200  # 2 hours

    desc = build_description(total_cho, total_fat, activity_duration)

    # carbohydrates per hour = total_cho / activity_duration * 3600 -> (3600/7200*3600)=1800
    assert str(round(total_cho / activity_duration * 60 * 60)) in desc
    assert str(round(total_fat / activity_duration * 60 * 60)) in desc

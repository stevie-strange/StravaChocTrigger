"""Re-fit the CHO / fat oxidation model from metabolic test stages.

Prints the coefficient arrays used in ``QueueTrigger1/__init__.py`` so a new
test only requires editing the stage table below and pasting the output.
Run with: ``python scripts/fit_metabolic_model.py``
"""
import numpy as np

# Spiroergometry, August 2026 (GitHub issue #26): power (W), CHO (g/h), fat (g/h), EE (kcal/h)
STAGES = [
    (125, 101.201, 18.044, 594.7),
    (150, 127.302, 16.371, 688.6),
    (175, 140.911, 17.825, 759.4),
    (200, 161.568, 17.735, 845.3),
    (225, 199.191, 9.321, 924.2),
    (250, 244.943, 0.0, 1028.8),
    (275, 261.239, 0.0, 1097.2),
    (300, 275.491, 0.0, 1157.1),
]

# Synthetic resting anchor at 0 W (intercepts of the previous model)
REST_CHO_G_PER_H = 24.48
REST_FAT_G_PER_H = 9.92

# Fat stages above this power are all zero (past Fatmin) and are left out of the
# cubic fit so they do not distort it; the model is clamped at zero instead.
FAT_FIT_MAX_POWER = 250


def main():
    """Fit the model and print the coefficient arrays."""
    power, cho, fat, energy = (np.array(col, dtype=float) for col in zip(*STAGES))

    cho_poly = np.polyfit(np.r_[0.0, power], np.r_[REST_CHO_G_PER_H, cho], 2)
    energy_poly = np.polyfit(power, energy, 1)

    fat_mask = power <= FAT_FIT_MAX_POWER
    fat_poly = np.polyfit(np.r_[0.0, power[fat_mask]],
                          np.r_[REST_FAT_G_PER_H, fat[fat_mask]], 3)

    np.set_printoptions(precision=12)
    print("CHO_POLY =", repr(cho_poly))
    print("ENERGY_KCAL_PER_H_POLY =", repr(energy_poly))
    print("FAT_POLY =", repr(fat_poly))

    grid = np.array([0, 50, 100, 150, 200, 250, 300, 350, 400, 500], dtype=float)
    cho_model = np.minimum(np.polyval(cho_poly, grid), np.polyval(energy_poly, grid) / 4.184)
    fat_model = np.clip(np.polyval(fat_poly, grid), 0, None)
    print("\nW   :", grid)
    print("CHO :", np.round(cho_model, 1))
    print("FAT :", np.round(fat_model, 1))


if __name__ == "__main__":
    main()

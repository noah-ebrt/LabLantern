import pytest

from app.rules import classify_severity


@pytest.mark.parametrize(
    "cvss, kev, fix, exposed, severity_label, expected",
    [
        # kritisch: KEV, oder CVSS >= 9 auf internet-erreichbarem Dienst
        (0.0, True, False, False, "", "kritisch"),
        (6.0, True, True, False, "", "kritisch"),
        (9.0, False, True, True, "", "kritisch"),
        (9.8, False, False, True, "", "kritisch"),
        # hoch: CVSS >= 7 internet-erreichbar mit Fix, CVSS >= 9 intern mit Fix
        (7.0, False, True, True, "", "hoch"),
        (9.0, False, True, False, "", "hoch"),
        # mittel: übrige Funde mit Fix (auch hoher CVSS intern unter 9)
        (8.8, False, True, False, "", "mittel"),
        (7.5, False, False, True, "", "info"),
        (5.5, False, True, False, "", "mittel"),
        (0.0, False, True, False, "", "mittel"),
        # info: Funde ohne Fix
        (9.5, False, False, False, "", "info"),
        (5.5, False, False, False, "", "info"),
    ],
)
def test_classification_follows_the_plan_table(cvss, kev, fix, exposed, severity_label, expected):
    assert classify_severity(cvss, kev, fix, exposed, severity_label) == expected


@pytest.mark.parametrize(
    "label, fix, exposed, expected",
    [
        # Ohne CVSS-Wert zählt das Schweregrad-Etikett des Advisories, damit nichts still herabgestuft wird.
        ("Critical", True, True, "kritisch"),
        ("Critical", True, False, "hoch"),
        ("High", True, True, "hoch"),
        ("High", True, False, "mittel"),
        ("Medium", True, True, "mittel"),
        ("Critical", False, False, "info"),
    ],
)
def test_missing_cvss_falls_back_to_severity_label(label, fix, exposed, expected):
    assert classify_severity(0.0, False, fix, exposed, label) == expected

import unittest

from juce8_megapatcher import PatchOutcome, juce_version_strings, parse_selection, probe_patchers


class ProbePatchersTest(unittest.TestCase):
    def test_probe_patchers_reports_outcomes_without_mutating_data(self):
        original = bytearray(b"abc")

        def mutating_patcher(data, pe):
            data[0] = ord("z")
            return PatchOutcome("mutating patch", "patched", "raw 0x0")

        outcomes = probe_patchers(original, object(), [mutating_patcher])

        self.assertEqual(original, bytearray(b"abc"))
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0].description, "mutating patch")
        self.assertEqual(outcomes[0].status, "patched")
        self.assertEqual(outcomes[0].detail, "raw 0x0")


class JuceVersionStringsTest(unittest.TestCase):
    def test_juce_version_strings_ignores_non_version_junk(self):
        data = b"prefix JUCE v8.H\x00 middle JUCE v8.0.8\x00"

        versions = juce_version_strings(data)

        self.assertEqual(versions, ["JUCE v8.0.8"])



class ParseSelectionTest(unittest.TestCase):
    def test_parse_selection_accepts_numbers_and_commas(self):
        slugs = ["filterverse", "temperance-pro", "kick-ninja"]

        selected = parse_selection("1, 3", slugs)

        self.assertEqual(selected, {"filterverse", "kick-ninja"})

    def test_parse_selection_accepts_all(self):
        slugs = ["filterverse", "temperance-pro"]

        selected = parse_selection("all", slugs)

        self.assertEqual(selected, {"filterverse", "temperance-pro"})

    def test_parse_selection_rejects_out_of_range_numbers(self):
        with self.assertRaises(ValueError):
            parse_selection("2", ["filterverse"])


if __name__ == "__main__":
    unittest.main()

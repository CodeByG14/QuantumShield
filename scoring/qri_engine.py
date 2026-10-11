"""Compatibility entry point for the Week 5 assessment engine.

The Week 3 QRI implementation consumed the old CBOM confidence shape and is no
longer compatible with the Week 5 finding/evidence models. The current CLI
writes assessment.json from the normalized discovery results.
"""

from scoring.assessment_writer import main


if __name__ == "__main__":
    main()

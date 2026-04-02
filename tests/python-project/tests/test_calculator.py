"""Tests for calculator module."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from calculator import add, divide, fibonacci


class TestAdd:
    def test_positive_numbers(self):
        assert add(2, 3) == 5

    def test_negative_numbers(self):
        assert add(-1, -2) == -3

    def test_floats(self):
        assert add(1.5, 2.5) == 4.0


class TestDivide:
    def test_basic_division(self):
        assert divide(10, 2) == 5.0

    def test_float_division(self):
        assert abs(divide(1, 3) - 0.3333333333) < 0.0001

    def test_divide_by_zero(self):
        with pytest.raises(ValueError, match="Cannot divide by zero"):
            divide(1, 0)


class TestFibonacci:
    def test_empty(self):
        assert fibonacci(0) == []

    def test_single(self):
        assert fibonacci(1) == [0]

    def test_ten(self):
        assert fibonacci(10) == [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]

    def test_negative(self):
        with pytest.raises(ValueError, match="Negative input"):
            fibonacci(-1)

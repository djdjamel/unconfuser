"""
NetDetect - All-in-one .NET Obfuscator, Protector, and Packer Detection Engine.
"""

from .analyzer import BinaryAnalyzer
from .detector import ObfuscatorDetector
from .reporter import DetectionReporter

__version__ = "1.0.0"
__all__ = ["BinaryAnalyzer", "ObfuscatorDetector", "DetectionReporter"]

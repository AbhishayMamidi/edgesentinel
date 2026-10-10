"""Capture module for EdgeSentinel."""

from edgesentinel.capture.base import BaseCaptureAdapter
from edgesentinel.capture.windows import WindowsCaptureAdapter
from edgesentinel.capture.linux import LinuxTcpdumpAdapter

__all__ = ["BaseCaptureAdapter", "WindowsCaptureAdapter", "LinuxTcpdumpAdapter"]

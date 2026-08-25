from __future__ import annotations

from abc import ABC, abstractmethod

from sark.registry import VectorSpec


class Backend(ABC):
    name: str

    @abstractmethod
    def vectors(self) -> list[VectorSpec]:
        """Return the vector registry contributed by this backend."""

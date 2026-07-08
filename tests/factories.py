"""factory_boy factories for building test data with sensible defaults, so tests
only need to specify the fields that matter to them."""
import factory

from netlook.core.models import Device


class DeviceFactory(factory.Factory):
    """Builds a Device seeded the way NetworkScanner really seeds one: hostname
    present in `names`, tagged with a source."""

    class Meta:
        model = Device

    hostname = "seed-host"
    ip = factory.Sequence(lambda n: f"10.0.0.{n + 1}")

    @factory.lazy_attribute
    def names(self):
        return {self.hostname: {"seed-source"}}

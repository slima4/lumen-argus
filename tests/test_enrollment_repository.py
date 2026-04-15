"""Tests for EnrollmentRepository.register() — focused on seat_cap enforcement."""

from lumen_argus.analytics import SeatCapExceeded
from tests.helpers import StoreTestCase, register_agent


class TestRegisterSeatCap(StoreTestCase):
    """EnrollmentRepository.register seat_cap enforcement."""

    def test_seat_cap_none_allows_unlimited(self):
        for i in range(10):
            register_agent(self.store, "agent_%d" % i, "machine_%d" % i, seat_cap=None)
        self.assertEqual(self.store.enrollment.count_agents(), 10)

    def test_seat_cap_refuses_over_limit(self):
        register_agent(self.store, "agent_1", "machine_1", seat_cap=2)
        register_agent(self.store, "agent_2", "machine_2", seat_cap=2)

        with self.assertRaises(SeatCapExceeded) as ctx:
            register_agent(self.store, "agent_3", "machine_3", seat_cap=2)

        self.assertEqual(ctx.exception.current, 2)
        self.assertEqual(ctx.exception.cap, 2)
        self.assertEqual(self.store.enrollment.count_agents(), 2)

    def test_seat_cap_allows_reregistration_of_same_machine(self):
        register_agent(self.store, "agent_1", "machine_1", seat_cap=1)
        for i in range(2, 5):
            register_agent(self.store, "agent_%d" % i, "machine_1", seat_cap=1)

        self.assertEqual(self.store.enrollment.count_agents(), 1)

    def test_seat_cap_zero_refuses_new_but_allows_reregistration(self):
        register_agent(self.store, "agent_1", "machine_1", seat_cap=None)

        # cap=0 → no new seats, but existing machine can still re-enroll.
        register_agent(self.store, "agent_2", "machine_1", seat_cap=0)
        self.assertEqual(self.store.enrollment.count_agents(), 1)

        with self.assertRaises(SeatCapExceeded) as ctx:
            register_agent(self.store, "agent_3", "machine_2", seat_cap=0)
        self.assertEqual(ctx.exception.current, 1)
        self.assertEqual(ctx.exception.cap, 0)

    def test_seat_cap_exceeded_carries_current_and_cap(self):
        register_agent(self.store, "agent_1", "machine_1", seat_cap=3)
        register_agent(self.store, "agent_2", "machine_2", seat_cap=3)
        register_agent(self.store, "agent_3", "machine_3", seat_cap=3)

        with self.assertRaises(SeatCapExceeded) as ctx:
            register_agent(self.store, "agent_4", "machine_4", seat_cap=3)

        self.assertEqual(ctx.exception.current, 3)
        self.assertEqual(ctx.exception.cap, 3)
        self.assertIn("3/3", str(ctx.exception))

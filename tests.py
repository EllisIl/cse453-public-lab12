import unittest
import control

class TestBellLaPadula(unittest.TestCase):
    # 1. TEST SIMPLE SECURITY (READ ACCESS)
    # Rule: Subject Level >= Object Level


    def test_no_read_up(self):
        """
        FAIL CASE: Low user tries to read High message. :(
        SeamanSam (Confidential) -> Secret Message
        Tests that a lower level user cannot read a higher level, higher level information is safe from a lower level double agent.
        """
        subject = "Confidential"
        obj = "Secret"
        # Expect false
        self.assertFalse(control.verify_read(subject, obj), 
                         "FAIL: Confidential user should NOT read Secret data")

    def test_read_down(self):
        """
        PASS CASE: High user tries to read Low message. :)
        AdmiralAbe (Secret) -> Confidential Message
        Tests that higher level users can read down to lower level information. Leadership can read reports and news directly without need the access to be changed.
        """
        subject = "Secret"
        obj = "Confidential"
        # Expect true
        self.assertTrue(control.verify_read(subject, obj), 
                        "FAIL: Secret user SHOULD be able to read Confidential data")

    def test_read_same(self):
        """
        PASS CASE: Equal levels.
        Checks that users can read their own level of messages
        """
        self.assertTrue(control.verify_read("Secret", "Secret"))

    # 2. TEST STAR PROPERTY (WRITE ACCESS)
    # Rule: Subject Level <= Object Level

    def test_no_write_down(self):
        """
        FAIL CASE: High user tries to write Low message.
        AdmiralAbe (Secret) -> Public Message
        This would prevent leaks to the public
        """
        subject = "Secret"
        obj = "Public"
        # Expect False 
        self.assertFalse(control.verify_write(subject, obj), 
                         "FAIL: Secret user should NOT write to Public (Write Down)")

    def test_write_same(self):
        """
        PASS CASE: Equal levels.
        Tests that a security level can write to the same level messages.
        """
        self.assertTrue(control.verify_write("Secret", "Secret"))

    def test_write_up(self):
        """
        PASS CASE: Low user writing to High bucket.
        Tests taht a lower user can write to a higher bucket. A Secret user comes across urgent information and wants to forward it to high command.

        """
        subject = "Confidential"
        obj = "Secret"
        self.assertTrue(control.verify_write(subject, obj), 
                        "FAIL: BLP allows writing up (blind write)")


    # 3. TEST UPDATE (READ + WRITE)
    # Rule: You must be able to READ it AND WRITE it.
    # Subject Level == Object Level


    # def test_update_permissions(self):
    #     """
    #     Update requires Reading (to see it) AND Writing (to save it).
    #     """
        
        # CASE A: AdmiralAbe (Secret) editing Confidential
        # The admiral reads a confidential message and wants to update intel that he recently found out.
        

        # CASE B: SeamanSam (Confidential) editing Secret
        # Sam knows that there is a secret report about German Uboats and wants to update it with his own findings.
       

        # CASE C: CaptainCharlie (Privileged) editing Privileged
        # Charlie created a report of what the men prefer to have for lunch and wants to update the message for the cooks.
       

if __name__ == '__main__':
    print("Running Bell-LaPadula Verification Tests...")
    unittest.main()
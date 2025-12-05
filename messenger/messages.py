########################################################################
# COMPONENT:
#    MESSAGES
# Author:
#    Br. Helfrich, Kyle Mueller, Lincoln Allen
# Summary: 
#    This class stores the notion of a collection of messages
########################################################################

import control, message

##################################################
# MESSAGES
# The collection of high-tech messages
##################################################
class Messages:

    ##################################################
    # MESSAGES CONSTRUCTOR
    # Read a file to fill the messages
    ##################################################
    def __init__(self, filename):
        self._messages = []
        self._read_messages(filename)

    ##################################################
    # MESSAGES :: DISPLAY
    # Display the list of messages
    ################################################## 
    def display(self):
        for m in self._messages:
            # Enforce Bell-LaPadula simple security property ("no read up"): only display properties for messages the current user may read.
            if control.can_read_message(m.get_id()):
                m.display_properties()

    ##################################################
    # MESSAGES :: SHOW
    # Show a single message
    ################################################## 
    def show(self, id):
        for m in self._messages:
            if m.get_id() == id:
                # Apply Bell-LaPadula read check.
                if control.can_read_message(id):
                    m.display_text()
                    return True
                # If the user is not cleared, behave as if the message does not exist to avoid leaking its presence.
                return False
        return False

    ##################################################
    # MESSAGES :: EXISTS
    # Determine whether a message with the given ID exists
    ##################################################
    def exists(self, id):
        for m in self._messages:
            if m.get_id() == id:
                return True
        return False

    ##################################################
    # MESSAGES :: UPDATE
    # Update a single message
    ################################################## 
    def update(self, id, text):
        for m in self._messages:
            if m.get_id() == id:
                # *-property: "no write down" – subject may write only if their clearance is <= the object's level.
                if control.can_write_message(id):
                    m.update_text(text)
                else:
                    print("ERROR: Access denied.")
                return

    ##################################################
    # MESSAGES :: REMOVE
    # Remove a single message
    ################################################## 
    def remove(self, id):
        for m in self._messages:
            if m.get_id() == id:
                if control.can_write_message(id):
                    m.clear()
                else:
                    print("ERROR: Access denied.")
                return

    ##################################################
    # MESSAGES :: ADD
    # Add a new message
    ################################################## 
    def add(self, text, author, date, text_control=None):
        m = message.Message(text, author, date)
        # Register the classification of the message with the access-control subsystem.
        control.register_message(m.get_id(), text_control, author)
        self._messages.append(m)

    ##################################################
    # MESSAGES :: READ MESSAGES
    # Read messages from a file
    ################################################## 
    def _read_messages(self, filename):
        try:
            with open(filename, "r") as f:
                for line in f:
                    text_control, author, date, text = line.split('|')
                    # text_control is the classification label stored in the messages.txt file.
                    self.add(text.rstrip('\r\n'), author, date, text_control)

        except FileNotFoundError:
            print(f"ERROR! Unable to open file \"{filename}\"")
            return

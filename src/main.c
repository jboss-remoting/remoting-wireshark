#include <stdint.h>
#include <stdbool.h>

// the order of these two is very important
#include <wireshark/config.h>
#include <epan/packet.h>

#include <wireshark/epan/dissectors/packet-tcp.h>

#include <gmodule.h>

G_MODULE_EXPORT gchar version[30] = "1.0";

static int proto_remoting = -1;

static const value_string msg_type_names[] = {
	{ 0x00, "Greeting" },
	{ 0x01, "Capabilities" },
	{ 0x02, "Auth Request" },
	{ 0x03, "Auth Challenge" },
	{ 0x04, "Auth Response" },
	{ 0x05, "Auth Complete" },
	{ 0x06, "Auth Rejected" },
	{ 0x07, "Start TLS" },
	{ 0x08, "NAK" },
	{ 0x10, "Channel Open Request" },
	{ 0x11, "Channel Open Ack" },
	{ 0x12, "Channel Open Service Not Found" },
	{ 0x13, "Channel Open Service Error" },
	{ 0x20, "Channel Shutdown Write" },
	{ 0x21, "Channel Close" },
	{ 0x30, "Message Data" },
	{ 0x31, "Message Window Open" },
	{ 0x32, "Message Async Close" },
	{ 0xF0, "Connection Alive" },
	{ 0xF1, "Connection Alive Ack" },
	{ 0xFF, "Connection Close" },
	{ 0, 0 }
};

static int hf_remoting_pkt_length = -1;
static int hf_remoting_pkt_type = -1;
static int hf_remoting_chanid = -1;
static int hf_remoting_msgid = -1;
static int hf_remoting_msg_flags = -1;
static int hf_remoting_msg_flag_new = -1;
static int hf_remoting_msg_flag_eof = -1;
static int hf_remoting_msg_flag_cancel = -1;
static int hf_remoting_msg_window = -1;

static gint ett_remoting = -1;

static void dissect_remoting_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Remoting");
	// clear info column
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		proto_item *ti = proto_tree_add_item(tree, proto_remoting, tvb, 0, -1, ENC_NA);
		proto_tree *remoting_tree = proto_item_add_subtree(ti, ett_remoting);
		proto_tree_add_item(remoting_tree, hf_remoting_pkt_length, tvb, 0, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(remoting_tree, hf_remoting_pkt_type, tvb, 4, 1, ENC_BIG_ENDIAN);
		uint8_t pkt_type = (uint8_t) tvb_get_guint8(tvb, 4);
		if (pkt_type >= 0x10 && pkt_type <= 0x3F) {
			proto_tree_add_item(remoting_tree, hf_remoting_chanid, tvb, 5, 4, ENC_BIG_ENDIAN);
			if (pkt_type >= 0x30) {
				proto_tree_add_item(remoting_tree, hf_remoting_msgid, tvb, 9, 2, ENC_BIG_ENDIAN);
				if (pkt_type == 0x30) {
					proto_tree_add_item(remoting_tree, hf_remoting_msg_flags, tvb, 11, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(remoting_tree, hf_remoting_msg_flag_new, tvb, 11, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(remoting_tree, hf_remoting_msg_flag_eof, tvb, 11, 1, ENC_BIG_ENDIAN);
					proto_tree_add_item(remoting_tree, hf_remoting_msg_flag_cancel, tvb, 11, 1, ENC_BIG_ENDIAN);
				} else if (pkt_type == 0x31) {
					proto_tree_add_item(remoting_tree, hf_remoting_msg_window, tvb, 11, 4, ENC_BIG_ENDIAN);
				}
			}
		}
	}
}

static guint get_remoting_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset) {
	return (guint) tvb_get_ntohl(tvb, offset) + 4;
}

static void dissect_remoting(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_remoting_message_len, dissect_remoting_msg);
}

void plugin_register(void) {
	// packet framing info
	static hf_register_info hf[] = {
		{ &hf_remoting_pkt_length, { "Remoting Length", "remoting.length",     FT_UINT32, BASE_DEC, 0,                    0x0, 0, HFILL }},
		{ &hf_remoting_pkt_type,   { "Remoting Type",   "remoting.type",       FT_UINT8,  BASE_HEX, VALS(msg_type_names), 0x0, 0, HFILL }},
		{ &hf_remoting_chanid,     { "Remoting Channel ID", "remoting.chanid", FT_UINT32, BASE_HEX, 0,                    0x0, 0, HFILL }},
		{ &hf_remoting_msgid,      { "Remoting Message ID", "remoting.msgid",  FT_UINT16, BASE_HEX, 0,                    0x0, 0, HFILL }},
		{ &hf_remoting_msg_flags,  { "Remoting Message Flags", "remoting.msgflags", FT_UINT8, BASE_HEX, 0,                0x0, 0, HFILL }},
		{ &hf_remoting_msg_flag_cancel, { "Cancelled",   "remoting.msgflags.cancel", FT_BOOLEAN, 8,    0,                    0x4, 0, HFILL }},
		{ &hf_remoting_msg_flag_new, { "New Message", "remoting.msgflags.new",    FT_BOOLEAN, 8,    0,                    0x2, 0, HFILL }},
		{ &hf_remoting_msg_flag_eof, { "End of Message", "remoting.msgflags.eom", FT_BOOLEAN, 8,    0,                    0x1, 0, HFILL }},
		{ &hf_remoting_msg_window, { "Remoting Window Adjustment", "remoting.msgwindow", FT_UINT32, BASE_DEC, 0,          0x0, 0, HFILL }},
	};
	// protocol subtree
	static gint *ett[] = { &ett_remoting };

	proto_remoting = proto_register_protocol("JBoss Remoting", "Remoting", "rem");
	proto_register_field_array(proto_remoting, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void plugin_reg_handoff(void) {
	static dissector_handle_t remoting_handle;
	remoting_handle = create_dissector_handle(dissect_remoting, proto_remoting);
	dissector_add_uint("tcp.port", 9999, remoting_handle);
}


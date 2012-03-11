--TM Protocal dissector

do

local tm_protocol = Proto("TM", "TM Protocol - tm2009, im software, popular in china")		--define protocol
local tm_data = Proto("TM.data", "TM Data - tm2009 data")		--define protocol

    local vs_protos = {
        [2] = "TM packet",
        [3] = "mtp3",
        [4] = "alcap",
        [5] = "h248",
        [6] = "ranap",
        [7] = "rnsap",
        [8] = "nbap"
    }
	--
    local vs_version= {
        [6] = "ranap",
        [7] = "rnsap",
        [8] = "nbap"
    }
    local vs_commands= {
        [2] = "TM packet",
        [3] = "mtp3",
        [4] = "alcap",
        [5] = "h248",
        [6] = "ranap",
        [7] = "rnsap",
        [8] = "nbap",
        [145] = "first command"		--ProtoField����f_command��Ӧ������
    }

    --��������ProtoField���󣬾����������в�Packet Details����������ʾ����Щ����
    local f_packet_header = ProtoField.bytes("tm.pkt.header","Packet Header","pkt header")
    --local f_packet_header = ProtoField.uint8("tm.packetheader","Packet Header",base.DEC)
    --local f_packet_header = ProtoField.uint8("tm.packetheader","Packet Header",base.HEX)

    local f_ver = ProtoField.bytes("tm.version","Protocol Version",base.HEX)
    --local f_ver = ProtoField.uint8("tm.version","Protocol Version",base.HEX,vs_version)
    --local f_ver = ProtoField.uint8("tm.version","Protocol Version",base.HEX)

    local f_text = ProtoField.string("tm.text","Text")

    --local f_command = ProtoField.bytes("tm.command","Command",base.HEX)
    local f_command = ProtoField.uint8("tm.command","Command",base.HEX,vs_commands)

    local f_packet_sequence = ProtoField.uint8("tm.pkt.sequence","Packet Sequence",base.DEC)

    local f_qq_num = ProtoField.uint8("tm.qqnum","QQ Number",base.DEC)

    local f_pro_data = ProtoField.bytes("tm.data","TM Data",base.DEC)

    local f_data_11bytes = ProtoField.bytes("tm.data","Unknow Filling","static 15 bytes")

    local f_data_key = ProtoField.bytes("tm.data","Key of TEA","16 bytes")

    local f_data_real = ProtoField.bytes("tm.data","Encrypted Data","some bytes")

    local f_packet_tailer = ProtoField.bytes("tm.pkt.tailer","Packet Tailer","pkt tailer")


        --��ProtoField����ӵ�Proto������
        tm_protocol.fields = {
			f_packet_header,
			f_ver,
			f_text,
			f_command,
			f_packet_sequence,
			f_qq_num,
		}
        tm_data.fields = {
			f_pro_data,
			f_data_11bytes,
			f_data_real,
			f_data_key, 
			f_packet_tailer 
		}

    --��Dissector.get�������Ի������һ��Э��Ľ������
    local data_dis = Dissector.get("data")

    local protos = {
    --    [2] = Dissector.get("TM"),
        [3] = Dissector.get("mtp3"),
        [4] = Dissector.get("alcap"),
        [5] = Dissector.get("h248"),
        [6] = Dissector.get("ranap"),
        [7] = Dissector.get("rnsap"),
        [8] = Dissector.get("nbap"),
        [9] = Dissector.get("rrc"),
        [10] = DissectorTable.get("sctp.ppi"):get_dissector(3), -- m3ua
        [11] = DissectorTable.get("ip.proto"):get_dissector(132), -- sctp
    }

    --ΪProto�������һ����Ϊdissector�ĺ�����
    --Wireshark���ÿ������ء����ݰ������������
    function tm_protocol.dissector(buf,pkt,root) 

        --����ǽ����ݵĵ�һ���ֽ�ת�����޷�������
        local proto_id = buf(0,1):uint()
		if proto_id == 2 then
			
			else
			return 
		end
		pkt.cols.protocol = "TM"		--display the columns of protocol
		--pkt.cols.info = "TM data"
        --root:add����Packet Details����������һ��Э��
        local t = root:add(tm_protocol,buf(0,buf:len()))
        --t:add����Packet Details����������һ�����ԣ�
        --��ָ��Ҫ�����������ʱPacket Bytes�����л�ѡ����Щ�ֽ�
        t:add(f_packet_header,buf(0,1))
        t:add(f_ver,buf(1,2))
        t:add(f_command,buf(3,2))
        t:add(f_packet_sequence,buf(5,2))
        t:add(f_qq_num,buf(7,4))

        local k = root:add(tm_data,buf(11,buf:len()-12))
		k:add(f_pro_data, buf(11,buf:len()-12))

		--if xxx
		--
		k:add(f_data_11bytes, buf(11, 11))
		--
		k:add(f_data_key, buf(22, 16))

		k:add(f_data_real, buf(38, 48))

        k:add(f_packet_tailer,buf(buf:len()-1,1))


        local dissector = protos[proto_id]

		--local w_info = TextWindow("hello,proto_id")
		--w_info:set(proto_id)


        if dissector ~= nil then
            dissector:call(buf(2):tvb(),pkt,root)
        elseif proto_id < 2 then
            t:add(f_text,buf(2))
            -- pkt.cols.info:set(buf(2,buf:len() - 3):string())
        else
            --��������һ��dissector
            --data_dis:call(buf(2):tvb(),pkt,root)
        end 

    end

    --���е�dissector�����ԡ�table������ʽ��֯�ģ�table��ʾ�ϼ�Э��
    local wtap_encap_table = DissectorTable.get("wtap_encap")
    --����ǻ��udpЭ���DissectorTable�������Զ˿ں�����
    local udp_encap_table = DissectorTable.get("udp.port")

--    wtap_encap_table:add(wtap.USER15,tm_protocol)
    wtap_encap_table:add(wtap.USER12,tm_protocol)
    --ΪUDP��7555�˿�ע�����Proto����
    --������Դ��Ŀ��ΪUDP7555�����ݰ����ͻ���������tm_protocol.dissector����
    udp_encap_table:add(8000,tm_protocol)


--function tm_protocol.dissector(buffer, pinfo, tree)
--		pinfo.cols.protocol = "TM"
--		pinfo.cols.info = "TM Data"
--		local subtree = tree:add(tm_protocol, buffer(), "TM-protocol")
--		subtree:add(buffer(0,0), "Message header: ")
--		subtree:add(buffer(0,1), "version"..buffer(0,1):unit())
--end

end

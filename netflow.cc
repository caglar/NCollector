#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <mysql++/mysql++.h>
#include <arpa/inet.h>

#include <string>
#include <iostream>
#include <map>
#include <vector>
#include <bitset>
#include <exception>

#include "netflow.h"

using std::cout;
using std::endl;
using std::vector;
using std::map;
using std::pair;
using std::string;
using std::bitset;
using std::make_pair;
using std::exception;

using mysqlpp::Query;
using mysqlpp::Connection;

struct template_cache tpl_cache;
map <int, pair<string, string> > index_field_type_map;
map <string, string> c_type_to_db_type;
map <string, int> c_type_to_c_type_len;
const int NfHdrV9Sz = sizeof(struct struct_header_v9);
const int NfDataHdrV9Sz = sizeof(struct data_hdr_v9);
const int NfTplHdrV9Sz = sizeof(struct template_hdr_v9);
const int NfOptTplHdrV9Sz = sizeof(struct options_template_hdr_v9);

void var_init ()
{
	cout << "tpl_cache " << sizeof(tpl_cache) << " " << tpl_cache.num << endl;
	tpl_cache.num = 0;

	c_type_to_db_type["int"] = "BIGINT";
	c_type_to_db_type["char"] = "BIGINT";
	c_type_to_db_type["short"] = "BIGINT";
	c_type_to_db_type["sockaddr_in6"] = "VARCHAR(40)";
	c_type_to_db_type["mac_addr"] = "VARCHAR(40)";

	c_type_to_c_type_len["int"] = 4;
	c_type_to_c_type_len["char"] = 1;
	c_type_to_c_type_len["short"] = 2;
	c_type_to_c_type_len["sockaddr_in6"] = 16;
	c_type_to_c_type_len["mac_addr"] = 6;

	index_field_type_map[1] = make_pair("IN_BYTE_1", "int");
	index_field_type_map[2] = make_pair("IN_PKTS_2", "int");
	index_field_type_map[3] = make_pair("FLOWS_3", "int");
	index_field_type_map[4] = make_pair("PROTOCOL_4", "char");
	index_field_type_map[5] = make_pair("TOS_5", "char");
	index_field_type_map[6] = make_pair("TCP_FLAGS_6", "char");
	index_field_type_map[7] = make_pair("L4_SRC_PORT_7", "short");
	index_field_type_map[8] = make_pair("IPV4_SRC_ADDR_8", "int");
	index_field_type_map[9] = make_pair("SRC_MASK_9", "char");
	index_field_type_map[10] = make_pair("INPUT_SNMP_10", "short");
	index_field_type_map[11] = make_pair("L4_DST_PORT_11", "short");
	index_field_type_map[12] = make_pair("IPV4_DST_ADDR_12", "int");
	index_field_type_map[13] = make_pair("DST_MASK_13", "char");
	index_field_type_map[14] = make_pair("OUTPUT_SNMP_14", "short");
	index_field_type_map[15] = make_pair("IPV4_NEXT_HOP_15", "int");
	index_field_type_map[16] = make_pair("SRC_AS_16", "short");
	index_field_type_map[17] = make_pair("DST_AS_17", "short");
	index_field_type_map[18] = make_pair("BGP_IPV4_NEXT_HOP_18", "int");
	index_field_type_map[19] = make_pair("MUL_DST_PKTS_19", "int");
	index_field_type_map[20] = make_pair("MUL_DST_BYTES_20", "int");
	index_field_type_map[21] = make_pair("LAST_SWITCHED_21", "int");
	index_field_type_map[22] = make_pair("FIRST_SWITCHED_22", "int");
	index_field_type_map[23] = make_pair("OUT_BYTES_23", "int");
	index_field_type_map[24] = make_pair("OUT_PKTS_24", "int");
	index_field_type_map[27] = make_pair("IPV6_SRC_ADDR_27", "sockaddr_in6");
	index_field_type_map[28] = make_pair("IPV6_DST_ADDR_28", "sockaddr_in6");
	index_field_type_map[29] = make_pair("IPV6_SRC_MASK_29", "int");
	index_field_type_map[30] = make_pair("IPV6_DST_MASK_30", "int");
	index_field_type_map[31] = make_pair("IPV6_FLOW_LABEL_31", "int3");
	index_field_type_map[32] = make_pair("ICMP_TYPE_32", "short");
	index_field_type_map[33] = make_pair("MUL_IGMP_TYPE_33", "char");
	index_field_type_map[34] = make_pair("SAMPLING_INTERVAL_34", "int");
	index_field_type_map[35] = make_pair("SAMPLING_ALGORITHM_35", "char");
	index_field_type_map[36] = make_pair("FLOW_ACTIVE_TIMEOUT_36", "short");
	index_field_type_map[37] = make_pair("FLOW_INACTIVE_TIMEOUT_37", "short");
	index_field_type_map[38] = make_pair("ENGINE_TYPE_38", "char");
	index_field_type_map[39] = make_pair("ENGINE_ID_39", "char");
	index_field_type_map[40] = make_pair("TOTAL_BYTES_EXP_40", "int");
	index_field_type_map[41] = make_pair("TOTAL_PKTS_EXP_41", "int");
	index_field_type_map[42] = make_pair("TOTAL_FLOWS_EXP_42", "int");
	index_field_type_map[46] = make_pair("", "");
	index_field_type_map[47] = make_pair("", "");
	index_field_type_map[48] = make_pair("FLOW_SAMPLER_ID_48", "int");
	index_field_type_map[49] = make_pair("FLOW_SAMPLER_MODE_49", "int");
	index_field_type_map[50] = make_pair("", "");
	index_field_type_map[51] = make_pair("", "");
	index_field_type_map[52] = make_pair("", "");
	index_field_type_map[53] = make_pair("", "");
	index_field_type_map[54] = make_pair("", "");
	index_field_type_map[55] = make_pair("DST_TOS_56", "char");
	index_field_type_map[56] = make_pair("IN_SRC_MAC_56", "char");
	index_field_type_map[57] = make_pair("OUT_DST_MAC_57", "char");
	index_field_type_map[58] = make_pair("SRC_VLAN_58", "char");
	index_field_type_map[59] = make_pair("DST_VLAN_59", "char");
	index_field_type_map[60] = make_pair("IP_PROTOCOL_VERSION_60", "char");
	index_field_type_map[61] = make_pair("DIRECTION_61", "char");
	index_field_type_map[62] = make_pair("IPV6_NEXT_HOP_62", "sockaddr_in6");
	index_field_type_map[63] = make_pair("BGP_V6_NEXT_HOP", "sockaddr_in6");
	index_field_type_map[64] = make_pair("", "");
	index_field_type_map[65] = make_pair("", "");
	index_field_type_map[66] = make_pair("", "");
	index_field_type_map[67] = make_pair("", "");
	index_field_type_map[68] = make_pair("", "");
	index_field_type_map[69] = make_pair("", "");
	index_field_type_map[70] = make_pair("MPLS_LABEL_1_70", "char");
	index_field_type_map[71] = make_pair("", "");
	index_field_type_map[72] = make_pair("", "");
	index_field_type_map[73] = make_pair("", "");
	index_field_type_map[74] = make_pair("", "");
	index_field_type_map[75] = make_pair("", "");
	index_field_type_map[76] = make_pair("", "");
	index_field_type_map[77] = make_pair("", "");
	index_field_type_map[78] = make_pair("", "");
	index_field_type_map[79] = make_pair("", "");
	index_field_type_map[80] = make_pair("IN_DST_MAC_80", "char");
	index_field_type_map[81] = make_pair("OUT_DST_MAC_81", "char");
	index_field_type_map[82] = make_pair("", "");
	index_field_type_map[83] = make_pair("", "");
	index_field_type_map[84] = make_pair("", "");
	index_field_type_map[85] = make_pair("", "");
	index_field_type_map[86] = make_pair("", "");
	index_field_type_map[87] = make_pair("", "");
	index_field_type_map[88] = make_pair("", "");
	index_field_type_map[89] = make_pair("FORWARDING_STATUS", "char");
}

void print_packet(unsigned char pkt[], int len)
{
	int i;
	for (i=0; i<len; i++)
	{
		printf("%02x", pkt[i]);
		if (i%4 == 0)
			printf(" ");
		if (i%16 == 0)
			printf("\n");
	}
	cout << endl;
}

void printbinary (unsigned char* bin, int len)
{
	for (int i = 0; i < len; i += 4)
	{
		bitset <8> bs1 ( *((unsigned char*)(bin+i)) );
		cout << bs1.to_string() << " ";
		bitset <8> bs2 ( *((unsigned char*)(bin+i+1)) );
		cout << bs2.to_string() << " ";	
		bitset <8> bs3 ( *((unsigned char*)(bin+i+2)) );
		cout << bs3.to_string() << " ";
		bitset <8> bs4 ( *((unsigned char*)(bin+i+3)) );
		cout << bs4.to_string() << endl;
	}
}

string table_name_suffix ()
{
	//cout << __LINE__ << " " << __FUNCTION__ << endl;
	char tmp[15];
	struct tm* nowtime;
	time_t nt;

	nt = time(NULL);
	nowtime = localtime(&nt);
	strftime(tmp, sizeof(tmp), "%Y%m%d%H%M%S", nowtime);	//template_20100706123524
	string suf("_");
	suf.append(tmp, 14);
	return suf;
}

void refresh_template_v9 ( int pos, struct template_hdr_v9* hdr )
{
	struct otpl_field* field_ptr = (struct otpl_field*) (hdr+1);
	int field_length = 0;
	tpl_cache.c[pos].template_id = ntohs(hdr->template_id);
	tpl_cache.c[pos].template_type = 0;
	tpl_cache.c[pos].num = ntohs (hdr->num);//Number of fields
	string table_name = "template" + table_name_suffix();
	memcpy (tpl_cache.c[pos].table_name, table_name.c_str(), table_name.size()+1);
	tpl_cache.c[pos].table_name[23] = '\0';

	memset(tpl_cache.c[pos].tpl_entry, 0, sizeof(struct otpl_field)*NF9_MAX_DEFINED_FIELD);
	for (int i = 0; i < tpl_cache.c[pos].num; i++)
	{
		tpl_cache.c[pos].tpl_entry[i].type = ntohs((field_ptr+i)->type);
		tpl_cache.c[pos].tpl_entry[i].len  = ntohs((field_ptr+i)->len);
		field_length += tpl_cache.c[pos].tpl_entry[i].len;
	}
	tpl_cache.c[pos].len = field_length;
}

int insert_template_v9 ( struct template_hdr_v9* hdr )
{
	//cout << __LINE__ << " " << __FUNCTION__ << endl;
	struct template_cache_entry *ptr, *prevptr = NULL;
	//struct template_field_v9 *field;
	int field_length = 0;
	//cout << "field count " << field_count << endl;

	struct otpl_field* field_ptr = (struct otpl_field*) (hdr+1);

	tpl_cache.c[tpl_cache.num].template_id = ntohs(hdr->template_id);
	tpl_cache.c[tpl_cache.num].template_type = 0;
	tpl_cache.c[tpl_cache.num].num = ntohs(hdr->num);//Number of fields
	string table_name = "template" + table_name_suffix();
	memcpy (tpl_cache.c[tpl_cache.num].table_name, table_name.c_str(), table_name.size()+1);
	tpl_cache.c[tpl_cache.num].table_name[23] = '\0';

	for (int i = 0; i < tpl_cache.c[tpl_cache.num].num; i++)
	{
		tpl_cache.c[tpl_cache.num].tpl_entry[i].type = ntohs((field_ptr+i)->type);
		tpl_cache.c[tpl_cache.num].tpl_entry[i].len  = ntohs((field_ptr+i)->len);
		//cout << __LINE__ << " field type " << tpl_cache.c[tpl_cache.num].tpl_entry[i].type \
		<< " field length " << tpl_cache.c[tpl_cache.num].tpl_entry[i].len << endl;
		field_length += tpl_cache.c[tpl_cache.num].tpl_entry[i].len;
	}
	tpl_cache.c[tpl_cache.num].len = field_length;
	//cout << __LINE__ << " value length is " << field_length << endl;
	tpl_cache.num++;
	//cout << "size of new entry : " << strlen(new_template_entry) << endl;
	return tpl_cache.num-1;//Just insert the template to return the position in the array
}

void parse_template_field (int pos, vector< pair<string, string> >& template_field)
{
	//cout << __LINE__ << " " << __FUNCTION__ << endl;
	struct template_field_v9* field_ptr = (struct template_field_v9*) tpl_cache.c[pos].tpl_entry;

	for (int i = 0; i < tpl_cache.c[pos].num; i++)
	{
		//cout << (field_ptr+i)->type << endl;
		template_field.push_back( index_field_type_map[(field_ptr+i)->type] );
	}
	//cout << __LINE__ << " " << __FUNCTION__ << endl;
}

void create_new_table (int pos)
{
	cout << __LINE__ << " " << __FUNCTION__ << endl;
	try
	{
		vector < pair<string, string> > template_field;
		/* pair< Field names, the initial type> */
		Connection conn("bw_nf_collector", "127.0.0.1", "root", "10241024cag");
		Query query(conn.query());

		parse_template_field(pos, template_field);

		string table_name(tpl_cache.c[pos].table_name);
		string sql = "CREATE TABLE IF NOT EXISTS " + table_name + " ( ";
		//out << sql << endl;
		vector< pair<string, string> >::iterator it;
		for ( it = template_field.begin() ; it < template_field.end(); it++ ) 
		{
			sql += it->first + " " + c_type_to_db_type[it->second] + " NOT NULL ,";
		}
		sql.erase (sql.size()-1, 1);
		//Remove the last comma
		sql += ") ENGINE = InnoDB CHARACTER SET utf8 COLLATE utf8_unicode_ci;";
		cout << sql << endl;
		query << sql;
		query.execute();
		conn.disconnect();
	}
	catch (const exception& er)
	{
		//record_to_logfile(db_log, er.what(), sql, __LINE__, __FUNCTION__, __FILE__);
		cout << __LINE__ << er.what() << endl;
	}
}

int
//Return the template position in the cache array
find_template_id (int id)
{
	cout << __LINE__ << " " << __FUNCTION__ << " id " << id << endl;
	for (int i = 0; i < tpl_cache.num; i++)
	{
		if (id == tpl_cache.c[i].template_id)
		{
			cout << "position " << i << endl;
			return i;
		}
	}
	return -1;
}

bool compare_field_same (int pos, struct template_hdr_v9* hdr)
{
	if (tpl_cache.c[pos].num != ntohs(hdr->num))
	{
		//cout << __LINE__ << " " << __FUNCTION__ << endl;
		return false;
	}
	struct otpl_field* field_ptr = (struct otpl_field*) (hdr+1);
	//Comparing each field type and length
	for (int i = 0; i < tpl_cache.c[pos].num; i++)
	{
		if ( (tpl_cache.c[pos].tpl_entry[i].type != ntohs((field_ptr+i)->type)))
		{
			return false;
		}
		if ( (tpl_cache.c[pos].tpl_entry[i].len != ntohs((field_ptr+i)->len)) )
		{
			return false;
		}
	}
	return true;
}

void handle_template_v9 (struct template_hdr_v9* hdr, u_int16_t type)
{
	struct template_cache_entry *tpl;
	int pos;

	//If you find a template
	cout << __LINE__ << " tpl id : " << ntohs(hdr->template_id) << endl;
	if ( -1 != (pos = find_template_id (ntohs(hdr->template_id))))
	{
		if ( !compare_field_same (pos, hdr) )
		{
			create_new_table(pos);
			refresh_template_v9(pos, hdr);
			//cout << __LINE__ << " " << __FUNCTION__ << endl;
		}
	}
	else
	{
		create_new_table(pos);
		pos = insert_template_v9(hdr);
		//cout << __LINE__ << " " << __FUNCTION__ << endl;
	}
	//cout << __LINE__ << " " << __FUNCTION__ << endl;
}

void handle_data_v9 (int pos, struct data_hdr_v9* hdr)
{
	int data_flowset_len = ntohs (hdr->flow_len);
	int data_len = tpl_cache.c[pos].len;
	int flowoff = 0;
	flowoff += sizeof (struct data_hdr_v9);
	while (flowoff + data_len <= data_flowset_len)
		//for (int i = 0; i < )
	{

	}
}

void process_v9_packet (unsigned char *pkt, int len /* 整个v9报文的长度 */)
{
	//cout << __LINE__ << " " << __FUNCTION__ << endl;
	//Save the location of the first pointer
	try
	{
		u_char *f_header = pkt; /* ptr to NetFlow packet header */ 
		struct template_cache_entry *tpl;
		struct template_hdr_v9 *template_hdr;
		struct options_template_hdr_v9 *opt_template_hdr;
		struct data_hdr_v9 *data_hdr;
		u_int16_t fid, off = 0, flowoff, flowsetlen, flow_type;
		Connection conn("bw_nf_collector", "127.0.0.1", "root", "10241024cag");
		Query query(conn.query());
		if (len < NfHdrV9Sz) 
		{
			cout << "INFO: discarding short NetFlow v9 packet" << endl;
			return;
		}
		//Move the pointer to skip 20 byte header v9
		pkt += NfHdrV9Sz;
		off += NfHdrV9Sz;

		//process_flowset:
		do {
			if (off+NfDataHdrV9Sz >= len)
			{
				cout << "INFO: unable to read next Flowset; incomplete NetFlow v9 packet" << endl;
				return;
			}
			data_hdr = (struct data_hdr_v9 *)pkt;
			fid = ntohs(data_hdr->flow_id);

			if (fid == 0) 
			{
				/* template */
				//cout << "template." << endl;
				print_packet (pkt, len-20);
				//printbinary    (pkt, len-20);
				unsigned char *tpl_ptr = pkt;

				flowoff = 0;
				//Skip the first 4 bytes of data
				tpl_ptr += NfDataHdrV9Sz;
				flowoff += NfDataHdrV9Sz;
				//This is the length of the template stream set
				flowsetlen = ntohs(data_hdr->flow_len);

				//cout << "flowsetlen is " << flowsetlen << endl;
				while (flowoff < flowsetlen) 
				{
					//Remove the template the second set of flow lines, is the first line of the template
					//record
					template_hdr = (struct template_hdr_v9 *) tpl_ptr;
					if ( off+flowsetlen > len )
					{
						cout << "INFO: unable to read next Template Flowset; incomplete NetFlow v9 packet" << endl;
						break;
						//return;
					}
					handle_template_v9(template_hdr, fid);
					//Move the pointer to the next template record
					tpl_ptr += sizeof(struct template_hdr_v9)+ntohs(template_hdr->num)*sizeof(struct template_field_v9); 
					//Calculate the length of the data have been processed, the template set of internal displacement flow
					flowoff += sizeof(struct template_hdr_v9)+ntohs(template_hdr->num)*sizeof(struct template_field_v9);
					//cout << "template record. " << endl;
				}

				pkt += flowsetlen; 
				off += flowsetlen; 
			}
			else if (fid >= 256) 
			{ /* data */
				//cout << "data." << endl;
				unsigned char *dat_ptr = pkt;
				//printbinary    (pkt, len-20);
				struct otpl_field* field_ptr;
				flowsetlen = ntohs(data_hdr->flow_len);
				if (off+flowsetlen > len) { 
					cout << __LINE__ << "INFO: unable to read next Data Flowset (incomplete NetFlow v9 packet)" << endl;
					return;
				}

				flowoff = 0;
				dat_ptr += NfDataHdrV9Sz;
				flowoff += NfDataHdrV9Sz;

				int pos = find_template_id(ntohs(data_hdr->flow_id));
				if (pos == -1)	//
				{
					//parse data packet
					cout << __LINE__ << " DEBUG ( default/core ): Discarded NetFlow V9 packet (R: unknown template " << endl;
					return;
				}
				else
				{
					string table_name (tpl_cache.c[pos].table_name);
					char tmp_str[46];

					string field_list;
					string value_list;
					//cout << "flowsetlen is " << flowsetlen << endl;
					//Set inside a data stream decoding cycle
					while (flowoff + tpl_cache.c[pos].len <= flowsetlen)
					{
						//cout << __LINE__ << " data record. record length is " << tpl_cache.c[pos].len << endl;
						//Out of loop for a record value
						for (int i = 0; i < tpl_cache.c[pos].num; i++)
						{
							field_list += index_field_type_map[tpl_cache.c[pos].tpl_entry[i].type].first + ", ";
							switch ( tpl_cache.c[pos].tpl_entry[i].len )
							{
								case 1:
									{
										//unsigned char a = *((unsigned char*)dat_ptr);
										sprintf(tmp_str, "%u", *((unsigned char*)dat_ptr));
										value_list.append(tmp_str);
										value_list += ", ";
										dat_ptr++;
										break;
									}
								case 2:
									{
										//unsigned short b = ntohs(*((unsigned short*)dat_ptr));
										sprintf (tmp_str, "%u", ntohs(*((unsigned short*)dat_ptr)));
										value_list.append (tmp_str);
										value_list += ", ";
										dat_ptr += 2;
										break;
									}
								case 4:
									{
										//unsigned int c = ntohl(*((unsigned int*)dat_ptr));
										sprintf (tmp_str, "%u", ntohl(*((unsigned int*)dat_ptr)));
										value_list.append (tmp_str);
										value_list += ", ";
										dat_ptr += 4;
										break;
									}
								case 6:
								case 16:
									{
										struct sockaddr_in6 e = *((sockaddr_in6*)dat_ptr);
										inet_ntop(AF_INET6, (void*)&e, tmp_str, sizeof(tmp_str));
										value_list.append ("\"");
										value_list.append (tmp_str);
										value_list.append ("\"");
										value_list += ", ";
										dat_ptr += 16;
										break;
									}
								default:
									{
										cout << __LINE__ << " unknown field length. " << endl;
										break;
									}
							}
						}
						cout << "IN BYTES: "  << index_field_type_map[tpl_cache.c[pos].tpl_entry[1].type].second<<endl;
						cout << "PROTO: "  << index_field_type_map[tpl_cache.c[pos].tpl_entry[2].type].second<<endl;
						cout << "IN PKTS: "  << index_field_type_map[tpl_cache.c[pos].tpl_entry[4].type].second<<endl;
						cout << "OUT PKTS: "  << index_field_type_map[tpl_cache.c[pos].tpl_entry[23].type].second<<endl;
						cout << "OUT BYTES: "  << index_field_type_map[tpl_cache.c[pos].tpl_entry[24].type].second<<endl;
						cout << "SRC PORT: "  << index_field_type_map[tpl_cache.c[pos].tpl_entry[7].type].second<<endl;
						cout << "DEST PORT: "  << index_field_type_map[tpl_cache.c[pos].tpl_entry[11].type].second<<endl;

						value_list.erase (value_list.size()-2, 2);	//Remove the last space and comma
						field_list.erase (field_list.size()-2, 2);	//Remove the last space and comma
						string sql = "INSERT INTO " + table_name + " (" +field_list+ ")" + " VALUES (" +value_list+ ");";
						value_list.clear();
						field_list.clear();
						cout << sql << endl;
						query << sql;
						query.execute();
						flowoff += tpl_cache.c[pos].len;
					}
				}
				//pkt += flowsetlen-flowoff; /* handling padding */
				pkt += flowsetlen;
				off += flowsetlen; 
			}
			else if (fid == 1) 
			{ /* options template */
				cout << "options." << endl;
			}
			else 
			{ /* unsupported flowset */
				cout << "unknown." << endl;
			}
		} while(off < len);
		conn.disconnect();
	}
	catch (const exception& er)
	{
		cout << __LINE__ << er.what() << endl;
	}
}

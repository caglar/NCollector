#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <mysql++/mysql++.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <string>
#include <iostream>
#include <map>
#include <vector>
#include <bitset>
#include <exception>

#include "netflow.h"

#define NUM_THREADS 2

using std::cout;
using std::cerr;
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

static struct template_cache tpl_cache;
static map <int, pair<string, string> > index_field_type_map;
static map <string, string> c_type_to_db_type;
static map <string, int> c_type_to_c_type_len;
static const int NfHdrV9Sz = sizeof(struct struct_header_v9);
static const int NfDataHdrV9Sz = sizeof(struct data_hdr_v9);
static const int NfTplHdrV9Sz = sizeof(struct template_hdr_v9);
static const int NfOptTplHdrV9Sz = sizeof(struct options_template_hdr_v9);

struct insq_thread_data {
  int thread_id;
  string sql;
  Query *query;
};

void
var_init ()
{
  cout << "Initializing the tpl_cache " << sizeof(tpl_cache) << " " << tpl_cache.num << endl;
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

void
print_packet(unsigned char pkt[], int len)
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

void
printbinary (unsigned char* bin, int len)
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

string
table_name_suffix ()
{
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

void
refresh_template_v9 ( int pos, struct template_hdr_v9* hdr )
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

int
insert_template_v9 (struct template_hdr_v9* hdr)
{
  //struct template_field_v9 *field;
  int field_length = 0;
  //cout << "field count " << field_count << endl;

  struct otpl_field* field_ptr = (struct otpl_field*) (hdr+1);

  tpl_cache.c[tpl_cache.num].template_id = ntohs(hdr->template_id);
  tpl_cache.c[tpl_cache.num].template_type = 0;
  tpl_cache.c[tpl_cache.num].num = ntohs(hdr->num);//Number of fields
  string table_name = "template" + table_name_suffix();
  memcpy (tpl_cache.c[tpl_cache.num].table_name, table_name.c_str(), table_name.size() + 1);
  tpl_cache.c[tpl_cache.num].table_name[23] = '\0';

  for (int i = 0; i < tpl_cache.c[tpl_cache.num].num; i++)
  {
    tpl_cache.c[tpl_cache.num].tpl_entry[i].type = ntohs((field_ptr+i)->type);
    tpl_cache.c[tpl_cache.num].tpl_entry[i].len  = ntohs((field_ptr+i)->len);
    field_length += tpl_cache.c[tpl_cache.num].tpl_entry[i].len;
  }
  tpl_cache.c[tpl_cache.num].len = field_length;


  tpl_cache.num++;

  //Just insert the template to return the position in the array
  return tpl_cache.num - 1;
}

void
parse_template_field (int pos, vector< pair<string, string> >& template_field)
{
  struct template_field_v9* field_ptr = (struct template_field_v9*) tpl_cache.c[pos].tpl_entry;
  cout << "The first part of first element of index_field_type_map: " << index_field_type_map[1].first << endl;

  for (int i = 0; i < tpl_cache.c[pos].num; i++)
  {
    template_field.push_back( index_field_type_map[(field_ptr+i)->type] );
  }
}

void
create_new_table (int pos, conf_params &cfg_params)
{
  cout << __LINE__ << " " << __FUNCTION__ << endl;
  try
  {
    vector < pair<string, string> > template_field;
    /* pair< Field names, the initial type> */
    Connection conn(cfg_params.db_params.dbname, cfg_params.db_params.host, cfg_params.db_params.username, cfg_params.db_params.password);
    Query query(conn.query());

    parse_template_field(pos, template_field);

    string table_name(tpl_cache.c[pos].table_name);
    string sql = "CREATE TABLE IF NOT EXISTS " + table_name + " ( ";

    vector< pair<string, string> >::iterator it;
    for ( it = template_field.begin() ; it < template_field.end(); it++ ) 
    {
      if ((it->second).length() > 0 && (it->first).length() > 0) {
        sql += it->first + " " + c_type_to_db_type[it->second] + " NOT NULL ,";
      }
    }

    //Remove the last comma:
    sql.erase (sql.size()-1, 1);

    sql += ") ENGINE = InnoDB CHARACTER SET utf8 COLLATE utf8_unicode_ci;";
    query << sql;
    query.execute();
    conn.disconnect();
  }
  catch (const exception& er)
  {
    cerr << __LINE__ << er.what() << endl;
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
      return i;
    }
  }
  return -1;
}

bool
compare_field_same (int pos, struct template_hdr_v9* hdr)
{
  if (tpl_cache.c[pos].num != ntohs(hdr->num))
  {
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

void 
handle_template_v9 (struct template_hdr_v9* hdr, u_int16_t type, conf_params &cfg_params)
{
  int pos;

  //If you find a template
  cout << __LINE__ << " tpl id : " << ntohs(hdr->template_id) << endl;
  if ( -1 != (pos = find_template_id (ntohs(hdr->template_id))))
  {
    if ( !compare_field_same (pos, hdr) )
    {
      if (cfg_params.enable_mysql) {
        create_new_table(pos, cfg_params);
      }
      refresh_template_v9(pos, hdr);
      //cout << __LINE__ << " " << __FUNCTION__ << endl;
    }
  }
  else
  {
    pos = insert_template_v9(hdr);
    //Assign the pos variable from the flow header
    if (cfg_params.enable_mysql) {
      create_new_table(pos, cfg_params);
    }
  }
}

void 
handle_data_v9 (int pos, struct data_hdr_v9* hdr)
{
  int data_flowset_len = ntohs (hdr->flow_len);
  int data_len = tpl_cache.c[pos].len;
  int flowoff = 0;
  flowoff += sizeof (struct data_hdr_v9);
  while (flowoff + data_len <= data_flowset_len)
  {
  }
}

void* insert_query(void *arg) {
  insq_thread_data *insq_tdata = static_cast<insq_thread_data *>(arg);
  Query *query = insq_tdata->query;
  string sql = insq_tdata->sql;
  *query << sql;
  if (query != NULL){
    query->execute();
  }
  return NULL;
}

void
send_row (map<string, string> row, conf_params &cfg_params, int sockfd, const struct sockaddr *dest_addr, socklen_t addrlen)
{
  map<string, string>::iterator iter;
  string s_row = "features ";

  for (iter = row.begin(); iter != row.end(); iter++) {
    s_row += (string)iter->first + ":" + (string)iter->second + " ";
  }

  s_row += "const=.01";
  if (cfg_params.debug_option) {
    cout << "Sent row is: " << s_row << endl;
  }
  int numbytes;
  if ((numbytes = sendto(sockfd, s_row.c_str(), s_row.length(), 0, dest_addr, addrlen)) == -1) {
    perror("talker: sendto");
    exit(1);
  }
}

void
process_v9_packet (unsigned char *pkt, int len, conf_params &cfg_params)
{
  //For multithreading purpose.
  pthread_t thread[NUM_THREADS];
  pthread_attr_t attr;

  /*  Initialize and set thread detached attribute */
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE); 
  insq_thread_data insq_tdata[NUM_THREADS];

  int rc;
  void *status;

  //cout << __LINE__ << " " << __FUNCTION__ << endl;
  //Save the location of the first pointer
  try
  {
    struct template_hdr_v9 *template_hdr;
    struct data_hdr_v9 *data_hdr;
    u_int16_t fid, off = 0, flowoff, flowsetlen;
    Connection conn(cfg_params.db_params.dbname, cfg_params.db_params.host, cfg_params.db_params.username, cfg_params.db_params.password);
    Query *query = new Query(conn.query());

    if (len < NfHdrV9Sz)
    {
      syslog(LOG_INFO, "Discarding short NetFlow v9 packet");
      return;
    }

    //Move the pointer to skip 20 byte header v9
    pkt += NfHdrV9Sz;
    off += NfHdrV9Sz;

    //Prepare UDP send socket functionality for replay
    int sockfd = 0;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    const char* replay_port = cfg_params.replay_port;

    if ((rv = getaddrinfo(cfg_params.replay_dest, replay_port, &hints, &servinfo)) != 0) {
      if (cfg_params.debug_option) {
        printf("Server name %s\n", cfg_params.replay_dest);
        printf("Replay port %s\n", replay_port);
      }
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
      exit(EXIT_FAILURE);
    }

    // loop through all the results and make a socket
    for(p = servinfo; p != NULL; p = p->ai_next) {
      if ((sockfd = socket(p->ai_family, p->ai_socktype,
                           p->ai_protocol)) == -1) {
        perror("talker: socket");
        continue;
      }
      break;
    }
    do {
      if (off+NfDataHdrV9Sz >= len)
      {
        syslog(LOG_NOTICE, "Unable to read next Flowset; incomplete NetFlow v9 packet");
        return;
      }
      data_hdr = (struct data_hdr_v9 *)pkt;
      fid = ntohs(data_hdr->flow_id);

      if (fid == 0)
      {
        /* template */
        print_packet (pkt, len-20);
        //printbinary    (pkt, len-20);
        unsigned char *tpl_ptr = pkt;

        flowoff = 0;
        //Skip the first 4 bytes of data
        tpl_ptr += NfDataHdrV9Sz;
        flowoff += NfDataHdrV9Sz;
        //This is the length of the template stream set
        flowsetlen = ntohs(data_hdr->flow_len);

        while (flowoff < flowsetlen)
        {
          //Remove the template the second set of flow lines, is the first line of the template
          //record
          template_hdr = (struct template_hdr_v9 *) tpl_ptr;
          if ( off + flowsetlen > len )
          {
            syslog(LOG_INFO, "Unable to read next Template Flowset; incomplete NetFlow v9 packet");
            break;
            //return;
          }
          handle_template_v9(template_hdr, fid, cfg_params);
          //Move the pointer to the next template record
          tpl_ptr += sizeof(struct template_hdr_v9) + ntohs(template_hdr->num)*sizeof(struct template_field_v9); 
          //Calculate the length of the data have been processed, the template set of internal displacement flow
          flowoff += sizeof(struct template_hdr_v9) + ntohs(template_hdr->num)*sizeof(struct template_field_v9);
        }
        pkt += flowsetlen; 
        off += flowsetlen; 
      }
      else if (fid >= 256) 
      { /* data */
        unsigned char *dat_ptr = pkt;
        //printbinary    (pkt, len-20);
        flowsetlen = ntohs(data_hdr->flow_len);
        if (off+flowsetlen > len) { 
          syslog(LOG_NOTICE, "Line %d: Unable to read next Data Flowset (incomplete NetFlow v9 packet)", __LINE__);
          return;
        }

        flowoff = 0;
        dat_ptr += NfDataHdrV9Sz;
        flowoff += NfDataHdrV9Sz;

        int pos = find_template_id(ntohs(data_hdr->flow_id));
        if (pos == -1)	//
        {
          //parse data packet
          syslog(LOG_INFO, "Line %d ( default/core ): Discarded NetFlow V9 packet (R: unknown template )", __LINE__);
          return;
        }
        else
        {
          string table_name (tpl_cache.c[pos].table_name);
          char tmp_str[46];
          map<string, string> row;

          string field_list;
          string value_list;
          //thread count:
          int tc = 0;
          //Set inside a data stream decoding cycle
          while (flowoff + tpl_cache.c[pos].len <= flowsetlen)
          {
            //Out of loop for a record value
            for (int i = 0; i < tpl_cache.c[pos].num; i++)
            {
              string field_name = index_field_type_map[tpl_cache.c[pos].tpl_entry[i].type].first;
              if (field_name.length() > 0) {
                field_list += field_name + ", ";
              }
              switch ( tpl_cache.c[pos].tpl_entry[i].len )
              {
               case 1:
                 {
                   sprintf(tmp_str, "%u", *((unsigned char*)dat_ptr));
                   row[index_field_type_map[tpl_cache.c[pos].tpl_entry[i].type].first] = tmp_str;
                   if (strcmp(tmp_str, "") != 0) {
                     value_list.append(tmp_str);
                     value_list += ", ";
                   }
                   dat_ptr++;
                   break;
                 }
               case 2:
                 {
                   sprintf (tmp_str, "%u", ntohs(*((unsigned short*)dat_ptr)));
                   row[index_field_type_map[tpl_cache.c[pos].tpl_entry[i].type].first] = tmp_str;
                   if (strcmp(tmp_str, "") != 0) {
                     value_list.append (tmp_str);
                     value_list += ", ";
                   }
                   dat_ptr += 2;
                   break;
                 }
               case 4:
                 {
                   sprintf (tmp_str, "%u", ntohl(*((unsigned int*)dat_ptr)));
                   row[index_field_type_map[tpl_cache.c[pos].tpl_entry[i].type].first] = tmp_str;
                   if (strcmp(tmp_str, "") != 0) {
                     value_list.append (tmp_str);
                     value_list += ", ";
                   }
                   dat_ptr += 4;
                   break;
                 }
               case 6:
               case 16:
                 {
                   sprintf(tmp_str, "%u", *((unsigned char*)dat_ptr));
                   row[index_field_type_map[tpl_cache.c[pos].tpl_entry[i].type].first] = tmp_str;

                   struct sockaddr_in6 e = *((sockaddr_in6*)dat_ptr);
                   inet_ntop(AF_INET6, (void*)&e, tmp_str, sizeof(tmp_str));
                   if (strcmp(tmp_str, "") != 0) {
                     value_list.append ("\"");
                     value_list.append (tmp_str);
                     value_list.append ("\"");
                     value_list += ", ";
                   }
                   dat_ptr += 16;
                   break;
                 }
               default:
                 {
                   syslog(LOG_NOTICE, "Line %d:  unknown field length. ", __LINE__);
                   break;
                 }
              }
            }

            send_row(row, cfg_params, sockfd, p->ai_addr, p->ai_addrlen);

            row.empty();

            value_list.erase (value_list.size()-2, 2);	//Remove the last space and comma
            field_list.erase (field_list.size()-2, 2);	//Remove the last space and comma
            if (cfg_params.enable_mysql) {
              string sql = "INSERT INTO " + table_name + " (" +field_list+ ")" + " VALUES (" +value_list+ ");";
              value_list.clear();
              field_list.clear();

              int t = tc % NUM_THREADS;
              insq_tdata[t].thread_id = t;
              insq_tdata[t].sql = sql;
              insq_tdata[t].query = query;
              rc = pthread_create(&thread[t], &attr, insert_query, (void *) &insq_tdata[t]);
              if (rc) {
                syslog(LOG_PERROR, "return code from pthread_create() is %d\n", rc);
                exit(-1);
              }
              if (cfg_params.debug_option) {
                cout << "Insert query is: " << sql << endl;
              }
              ///              insert_query(sql, query);
            }

            tc++;
            flowoff += tpl_cache.c[pos].len;
          }
        }
        /* handling padding */
        pkt += flowsetlen;
        off += flowsetlen; 
      }
      else if (fid == 1) 
      {
        /* options template */
        cout << "options." << endl;
      }
      else 
      {
        /* unsupported flowset */
        cout << "unknown." << endl;
      }
    } while(off < len);
    
    //Wait for threads to finish
    pthread_attr_destroy(&attr);
    for(int t = 0; t<NUM_THREADS; t++) {
      rc = pthread_join(thread[t], &status);
      if (rc) {
        syslog(LOG_PERROR, "return code from pthread_join() is %d\n", rc);
        exit(-1);
      }
    }
    pthread_exit(NULL);
    
    if (cfg_params.enable_replay) {
      close(sockfd);
    }
    conn.disconnect();
  }
  catch (const exception& er)
  {
    cerr << __LINE__ << er.what() << endl;
  }

}

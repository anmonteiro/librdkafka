/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2015, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _RDKAFKA_REQUEST_H_
#define _RDKAFKA_REQUEST_H_

#include "rdkafka_cgrp.h"
#include "rdkafka_feature.h"


#define RD_KAFKA_ERR_ACTION_PERMANENT 0x1  /* Permanent error */
#define RD_KAFKA_ERR_ACTION_IGNORE    0x2  /* Error can be ignored */
#define RD_KAFKA_ERR_ACTION_REFRESH   0x4  /* Refresh state (e.g., metadata) */
#define RD_KAFKA_ERR_ACTION_RETRY     0x8  /* Retry request after backoff */
#define RD_KAFKA_ERR_ACTION_INFORM    0x10 /* Inform application about err */
#define RD_KAFKA_ERR_ACTION_SPECIAL                                            \
        0x20 /* Special-purpose, depends on context */
#define RD_KAFKA_ERR_ACTION_MSG_NOT_PERSISTED 0x40 /* ProduceReq msg status */
#define RD_KAFKA_ERR_ACTION_MSG_POSSIBLY_PERSISTED                             \
        0x80                                    /* ProduceReq msg status */
#define RD_KAFKA_ERR_ACTION_MSG_PERSISTED 0x100 /* ProduceReq msg status */
#define RD_KAFKA_ERR_ACTION_FATAL         0x200 /**< Fatal error */
#define RD_KAFKA_ERR_ACTION_END           0     /* var-arg sentinel */

/** @macro bitmask of the message persistence flags */
#define RD_KAFKA_ERR_ACTION_MSG_FLAGS                                          \
        (RD_KAFKA_ERR_ACTION_MSG_NOT_PERSISTED |                               \
         RD_KAFKA_ERR_ACTION_MSG_POSSIBLY_PERSISTED |                          \
         RD_KAFKA_ERR_ACTION_MSG_PERSISTED)

int rd_kafka_err_action(rd_kafka_broker_t *rkb,
                        rd_kafka_resp_err_t err,
                        const rd_kafka_buf_t *request,
                        ...);


const char *rd_kafka_actions2str(int actions);

rd_kafka_topic_partition_list_t *
rd_kafka_buf_read_topic_partitions(rd_kafka_buf_t *rkbuf,
                                   size_t estimated_part_cnt,
                                   rd_bool_t read_offset,
                                   rd_bool_t read_part_errs);
int rd_kafka_buf_write_topic_partitions(
    rd_kafka_buf_t *rkbuf,
    const rd_kafka_topic_partition_list_t *parts,
    rd_bool_t skip_invalid_offsets,
    rd_bool_t only_invalid_offsets,
    rd_bool_t write_Offset,
    rd_bool_t write_Epoch,
    rd_bool_t write_Metadata);

rd_kafka_resp_err_t
rd_kafka_FindCoordinatorRequest(rd_kafka_broker_t *rkb,
                                rd_kafka_coordtype_t coordtype,
                                const char *coordkey,
                                rd_kafka_replyq_t replyq,
                                rd_kafka_resp_cb_t *resp_cb,
                                void *opaque);

static rd_kafka_resp_err_t rd_kafka_parse_ListOffsets(rd_kafka_buf_t *rkbuf,rd_kafka_list_offset_list_t *offsets) {
        const int log_decode_errors = LOG_ERR;
        int32_t TopicArrayCnt;
        int16_t api_version;
        rd_kafka_resp_err_t all_err = RD_KAFKA_RESP_ERR_NO_ERROR;

        api_version = rkbuf->rkbuf_reqhdr.ApiVersion;

        if (api_version >= 2)
                rd_kafka_buf_read_throttle_time(rkbuf);

        /* NOTE:
         * Broker may return offsets in a different constellation than
         * in the original request .*/

        rd_kafka_buf_read_i32(rkbuf, &TopicArrayCnt);
        while (TopicArrayCnt-- > 0) {
                rd_kafkap_str_t ktopic;
                int32_t PartArrayCnt;
                char *topic_name;

                rd_kafka_buf_read_str(rkbuf, &ktopic);
                rd_kafka_buf_read_i32(rkbuf, &PartArrayCnt);

                RD_KAFKAP_STR_DUPA(&topic_name, &ktopic);

                while (PartArrayCnt-- > 0) {
                        int32_t kpartition;
                        int16_t ErrorCode;
                        int32_t OffsetArrayCnt;
                        int64_t Offset = -1;
                        int64_t Timestamp = -1;
                        rd_kafka_list_offset_t *list_offset;

                        rd_kafka_buf_read_i32(rkbuf, &kpartition);
                        rd_kafka_buf_read_i16(rkbuf, &ErrorCode);

                        if (api_version >= 1) {
                                rd_kafka_buf_read_i64(rkbuf, &Timestamp);
                                rd_kafka_buf_read_i64(rkbuf, &Offset);
                        } else if (api_version == 0) {
                                rd_kafka_buf_read_i32(rkbuf, &OffsetArrayCnt);
                                /* We only request one offset so just grab
                                 * the first one. */
                                while (OffsetArrayCnt-- > 0)
                                        rd_kafka_buf_read_i64(rkbuf, &Offset);
                        } else {
                                rd_kafka_assert(NULL, !*"NOTREACHED");
                        }
                        
                        list_offset = rd_kafka_list_offset_list_add(
                            offsets);
                        list_offset->timestamp = Timestamp;
                        list_offset->topicPartition.partition = kpartition;
                        list_offset->topicPartition.topic = strdup(topic_name);
                        list_offset->topicPartition.err    = ErrorCode;
                        list_offset->topicPartition.offset = Offset;

                        if (ErrorCode && !all_err)
                                all_err = ErrorCode;
                }
        }

        return all_err;

err_parse:
        return rkbuf->rkbuf_err;
};

static rd_kafka_resp_err_t rd_kafka_handle_ListOffsets(rd_kafka_t *rk,
                            rd_kafka_broker_t *rkb,
                            rd_kafka_resp_err_t err,
                            rd_kafka_buf_t *rkbuf,
                            rd_kafka_buf_t *request,
                            rd_kafka_topic_partition_list_t *offsets,
                            int *actionsp){

        int actions;

        if (!err)
                err = rd_kafka_parse_ListOffsets(rkbuf, offsets);
        if (!err)
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        actions = rd_kafka_err_action(
            rkb, err, request, RD_KAFKA_ERR_ACTION_PERMANENT,
            RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART,

            RD_KAFKA_ERR_ACTION_REFRESH,
            RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION,

            RD_KAFKA_ERR_ACTION_REFRESH,
            RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE,

            RD_KAFKA_ERR_ACTION_REFRESH, RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR,

            RD_KAFKA_ERR_ACTION_REFRESH, RD_KAFKA_RESP_ERR_OFFSET_NOT_AVAILABLE,

            RD_KAFKA_ERR_ACTION_REFRESH | RD_KAFKA_ERR_ACTION_RETRY,
            RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE,

            RD_KAFKA_ERR_ACTION_REFRESH | RD_KAFKA_ERR_ACTION_RETRY,
            RD_KAFKA_RESP_ERR_FENCED_LEADER_EPOCH,

            RD_KAFKA_ERR_ACTION_RETRY, RD_KAFKA_RESP_ERR__TRANSPORT,

            RD_KAFKA_ERR_ACTION_RETRY, RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT,

            RD_KAFKA_ERR_ACTION_END);

        if (actionsp)
                *actionsp = actions;

        if (rkb)
                rd_rkb_dbg(
                    rkb, TOPIC, "OFFSET", "OffsetRequest failed: %s (%s)",
                    rd_kafka_err2str(err), rd_kafka_actions2str(actions));

        if (actions & RD_KAFKA_ERR_ACTION_REFRESH) {
                char tmp[256];
                /* Re-query for leader */
                rd_snprintf(tmp, sizeof(tmp), "ListOffsetsRequest failed: %s",
                            rd_kafka_err2str(err));
                rd_kafka_metadata_refresh_known_topics(rk, NULL,
                                                       rd_true /*force*/, tmp);
        }

        if ((actions & RD_KAFKA_ERR_ACTION_RETRY) &&
            rd_kafka_buf_retry(rkb, request))
                return RD_KAFKA_RESP_ERR__IN_PROGRESS;

        return err;
};
static rd_kafka_resp_err_t
rd_kafka_make_ListOffsetsRequest(rd_kafka_broker_t *rkb,
                                 rd_kafka_buf_t *rkbuf,
                                 void *make_opaque) {
        const rd_kafka_topic_partition_list_t *partitions =
            (const rd_kafka_topic_partition_list_t *)make_opaque;
        int i;
        size_t of_TopicArrayCnt = 0, of_PartArrayCnt = 0;
        const char *last_topic = "";
        int32_t topic_cnt = 0, part_cnt = 0;
        int16_t ApiVersion;

        ApiVersion = rd_kafka_broker_ApiVersion_supported(
            rkb, RD_KAFKAP_ListOffsets, 0, 2, NULL);
        if (ApiVersion == -1)
                return RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE;

        /* ReplicaId */
        rd_kafka_buf_write_i32(rkbuf, -1);

        /* IsolationLevel */
        if (ApiVersion >= 2)
                rd_kafka_buf_write_i8(rkbuf,
                                      rkb->rkb_rk->rk_conf.isolation_level);

        /* TopicArrayCnt */
        of_TopicArrayCnt = rd_kafka_buf_write_i32(rkbuf, 0); /* updated later */

        for (i = 0; i < partitions->cnt; i++) {
                const rd_kafka_topic_partition_t *rktpar =
                    &partitions->elems[i];

                if (strcmp(rktpar->topic, last_topic)) {
                        /* Finish last topic, if any. */
                        if (of_PartArrayCnt > 0)
                                rd_kafka_buf_update_i32(rkbuf, of_PartArrayCnt,
                                                        part_cnt);

                        /* Topic */
                        rd_kafka_buf_write_str(rkbuf, rktpar->topic, -1);
                        topic_cnt++;
                        last_topic = rktpar->topic;
                        /* New topic so reset partition count */
                        part_cnt = 0;

                        /* PartitionArrayCnt: updated later */
                        of_PartArrayCnt = rd_kafka_buf_write_i32(rkbuf, 0);
                }

                /* Partition */
                rd_kafka_buf_write_i32(rkbuf, rktpar->partition);
                part_cnt++;

                /* Time/Offset */
                rd_kafka_buf_write_i64(rkbuf, rktpar->offset);

                if (ApiVersion == 0) {
                        /* MaxNumberOfOffsets */
                        rd_kafka_buf_write_i32(rkbuf, 1);
                }
        }

        if (of_PartArrayCnt > 0) {
                rd_kafka_buf_update_i32(rkbuf, of_PartArrayCnt, part_cnt);
                rd_kafka_buf_update_i32(rkbuf, of_TopicArrayCnt, topic_cnt);
        }

        rd_kafka_buf_ApiVersion_set(rkbuf, ApiVersion, 0);

        rd_rkb_dbg(rkb, TOPIC, "OFFSET",
                   "ListOffsetsRequest (v%hd, opv %d) "
                   "for %" PRId32 " topic(s) and %" PRId32 " partition(s)",
                   ApiVersion, rkbuf->rkbuf_replyq.version, topic_cnt,
                   partitions->cnt);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
};
static void rd_kafka_ListOffsetsRequest(rd_kafka_broker_t *rkb,
                                 rd_kafka_topic_partition_list_t *partitions,
                                 rd_kafka_replyq_t replyq,
                                 rd_kafka_resp_cb_t *resp_cb,
                                 void *opaque) {
        rd_kafka_buf_t *rkbuf;
        rd_kafka_topic_partition_list_t *make_parts;

        make_parts = rd_kafka_topic_partition_list_copy(partitions);
        rd_kafka_topic_partition_list_sort_by_topic(make_parts);

        rkbuf = rd_kafka_buf_new_request(
            rkb, RD_KAFKAP_ListOffsets, 1,
            /* ReplicaId + IsolationLevel + topicArrayCount + topicArrayCount*(topicName + partition_count*(partitionIndex + Timestamp + MaxnumOffsets))*/
            /*topicArrayCount*partition_count evaluates to total topicPartitions*/
            /*ReplicaId + IsolationLevel + topicArrayCount + topicArrayCount*topic + total_partitions*(partitionIndex+Timestamp+maxnumOffsets)*/

            /* ReplicaId+IsolationLevel+TopicArrayCnt+Topic */
            4 + 1 + 4 + 100 +
                /* PartArrayCnt */
                4 +
                /* partition_cnt * Partition+Time+MaxNumOffs */
                (make_parts->cnt * (4 + 8 + 4)));

        /* Postpone creating the request contents until time to send,
         * at which time the ApiVersion is known. */
        rd_kafka_buf_set_maker(rkbuf, rd_kafka_make_ListOffsetsRequest,
                               make_parts,
                               rd_kafka_topic_partition_list_destroy_free);

        rd_kafka_broker_buf_enq_replyq(rkb, rkbuf, replyq, resp_cb, opaque);
};

rd_kafka_resp_err_t
rd_kafka_handle_OffsetFetch(rd_kafka_t *rk,
                            rd_kafka_broker_t *rkb,
                            rd_kafka_resp_err_t err,
                            rd_kafka_buf_t *rkbuf,
                            rd_kafka_buf_t *request,
                            rd_kafka_topic_partition_list_t **offsets,
                            rd_bool_t update_toppar,
                            rd_bool_t add_part,
                            rd_bool_t allow_retry);

void rd_kafka_op_handle_OffsetFetch(rd_kafka_t *rk,
                                    rd_kafka_broker_t *rkb,
                                    rd_kafka_resp_err_t err,
                                    rd_kafka_buf_t *rkbuf,
                                    rd_kafka_buf_t *request,
                                    void *opaque);

void rd_kafka_OffsetFetchRequest(rd_kafka_broker_t *rkb,
                                 const char *group_id,
                                 rd_kafka_topic_partition_list_t *parts,
                                 rd_bool_t require_stable_offsets,
                                 int timeout,
                                 rd_kafka_replyq_t replyq,
                                 rd_kafka_resp_cb_t *resp_cb,
                                 void *opaque);

rd_kafka_resp_err_t
rd_kafka_handle_OffsetCommit(rd_kafka_t *rk,
                             rd_kafka_broker_t *rkb,
                             rd_kafka_resp_err_t err,
                             rd_kafka_buf_t *rkbuf,
                             rd_kafka_buf_t *request,
                             rd_kafka_topic_partition_list_t *offsets,
                             rd_bool_t ignore_cgrp);

int rd_kafka_OffsetCommitRequest(rd_kafka_broker_t *rkb,
                                 rd_kafka_consumer_group_metadata_t *cgmetadata,
                                 rd_kafka_topic_partition_list_t *offsets,
                                 rd_kafka_replyq_t replyq,
                                 rd_kafka_resp_cb_t *resp_cb,
                                 void *opaque,
                                 const char *reason);

rd_kafka_resp_err_t
rd_kafka_OffsetDeleteRequest(rd_kafka_broker_t *rkb,
                             /** (rd_kafka_DeleteConsumerGroupOffsets_t*) */
                             const rd_list_t *del_grpoffsets,
                             rd_kafka_AdminOptions_t *options,
                             char *errstr,
                             size_t errstr_size,
                             rd_kafka_replyq_t replyq,
                             rd_kafka_resp_cb_t *resp_cb,
                             void *opaque);


void rd_kafka_JoinGroupRequest(rd_kafka_broker_t *rkb,
                               const rd_kafkap_str_t *group_id,
                               const rd_kafkap_str_t *member_id,
                               const rd_kafkap_str_t *group_instance_id,
                               const rd_kafkap_str_t *protocol_type,
                               const rd_list_t *topics,
                               rd_kafka_replyq_t replyq,
                               rd_kafka_resp_cb_t *resp_cb,
                               void *opaque);


void rd_kafka_LeaveGroupRequest(rd_kafka_broker_t *rkb,
                                const char *group_id,
                                const char *member_id,
                                rd_kafka_replyq_t replyq,
                                rd_kafka_resp_cb_t *resp_cb,
                                void *opaque);
void rd_kafka_handle_LeaveGroup(rd_kafka_t *rk,
                                rd_kafka_broker_t *rkb,
                                rd_kafka_resp_err_t err,
                                rd_kafka_buf_t *rkbuf,
                                rd_kafka_buf_t *request,
                                void *opaque);

void rd_kafka_SyncGroupRequest(rd_kafka_broker_t *rkb,
                               const rd_kafkap_str_t *group_id,
                               int32_t generation_id,
                               const rd_kafkap_str_t *member_id,
                               const rd_kafkap_str_t *group_instance_id,
                               const rd_kafka_group_member_t *assignments,
                               int assignment_cnt,
                               rd_kafka_replyq_t replyq,
                               rd_kafka_resp_cb_t *resp_cb,
                               void *opaque);
void rd_kafka_handle_SyncGroup(rd_kafka_t *rk,
                               rd_kafka_broker_t *rkb,
                               rd_kafka_resp_err_t err,
                               rd_kafka_buf_t *rkbuf,
                               rd_kafka_buf_t *request,
                               void *opaque);

rd_kafka_error_t *rd_kafka_ListGroupsRequest(rd_kafka_broker_t *rkb,
                                             int16_t max_ApiVersion,
                                             const char **states,
                                             size_t states_cnt,
                                             rd_kafka_replyq_t replyq,
                                             rd_kafka_resp_cb_t *resp_cb,
                                             void *opaque);

rd_kafka_error_t *rd_kafka_DescribeGroupsRequest(rd_kafka_broker_t *rkb,
                                                 int16_t max_ApiVersion,
                                                 char **groups,
                                                 size_t group_cnt,
                                                 rd_kafka_replyq_t replyq,
                                                 rd_kafka_resp_cb_t *resp_cb,
                                                 void *opaque);


void rd_kafka_HeartbeatRequest(rd_kafka_broker_t *rkb,
                               const rd_kafkap_str_t *group_id,
                               int32_t generation_id,
                               const rd_kafkap_str_t *member_id,
                               const rd_kafkap_str_t *group_instance_id,
                               rd_kafka_replyq_t replyq,
                               rd_kafka_resp_cb_t *resp_cb,
                               void *opaque);

rd_kafka_resp_err_t rd_kafka_MetadataRequest(rd_kafka_broker_t *rkb,
                                             const rd_list_t *topics,
                                             const char *reason,
                                             rd_bool_t allow_auto_create_topics,
                                             rd_bool_t cgrp_update,
                                             rd_kafka_op_t *rko);

rd_kafka_resp_err_t
rd_kafka_handle_ApiVersion(rd_kafka_t *rk,
                           rd_kafka_broker_t *rkb,
                           rd_kafka_resp_err_t err,
                           rd_kafka_buf_t *rkbuf,
                           rd_kafka_buf_t *request,
                           struct rd_kafka_ApiVersion **apis,
                           size_t *api_cnt);
void rd_kafka_ApiVersionRequest(rd_kafka_broker_t *rkb,
                                int16_t ApiVersion,
                                rd_kafka_replyq_t replyq,
                                rd_kafka_resp_cb_t *resp_cb,
                                void *opaque);

void rd_kafka_SaslHandshakeRequest(rd_kafka_broker_t *rkb,
                                   const char *mechanism,
                                   rd_kafka_replyq_t replyq,
                                   rd_kafka_resp_cb_t *resp_cb,
                                   void *opaque);

void rd_kafka_handle_SaslAuthenticate(rd_kafka_t *rk,
                                      rd_kafka_broker_t *rkb,
                                      rd_kafka_resp_err_t err,
                                      rd_kafka_buf_t *rkbuf,
                                      rd_kafka_buf_t *request,
                                      void *opaque);
void rd_kafka_SaslAuthenticateRequest(rd_kafka_broker_t *rkb,
                                      const void *buf,
                                      size_t size,
                                      rd_kafka_replyq_t replyq,
                                      rd_kafka_resp_cb_t *resp_cb,
                                      void *opaque);

int rd_kafka_ProduceRequest(rd_kafka_broker_t *rkb,
                            rd_kafka_toppar_t *rktp,
                            const rd_kafka_pid_t pid,
                            uint64_t epoch_base_msgid);

rd_kafka_resp_err_t
rd_kafka_CreateTopicsRequest(rd_kafka_broker_t *rkb,
                             const rd_list_t *new_topics /*(NewTopic_t*)*/,
                             rd_kafka_AdminOptions_t *options,
                             char *errstr,
                             size_t errstr_size,
                             rd_kafka_replyq_t replyq,
                             rd_kafka_resp_cb_t *resp_cb,
                             void *opaque);

rd_kafka_resp_err_t
rd_kafka_DeleteTopicsRequest(rd_kafka_broker_t *rkb,
                             const rd_list_t *del_topics /*(DeleteTopic_t*)*/,
                             rd_kafka_AdminOptions_t *options,
                             char *errstr,
                             size_t errstr_size,
                             rd_kafka_replyq_t replyq,
                             rd_kafka_resp_cb_t *resp_cb,
                             void *opaque);

rd_kafka_resp_err_t rd_kafka_CreatePartitionsRequest(
    rd_kafka_broker_t *rkb,
    const rd_list_t *new_parts /*(NewPartitions_t*)*/,
    rd_kafka_AdminOptions_t *options,
    char *errstr,
    size_t errstr_size,
    rd_kafka_replyq_t replyq,
    rd_kafka_resp_cb_t *resp_cb,
    void *opaque);

rd_kafka_resp_err_t
rd_kafka_AlterConfigsRequest(rd_kafka_broker_t *rkb,
                             const rd_list_t *configs /*(ConfigResource_t*)*/,
                             rd_kafka_AdminOptions_t *options,
                             char *errstr,
                             size_t errstr_size,
                             rd_kafka_replyq_t replyq,
                             rd_kafka_resp_cb_t *resp_cb,
                             void *opaque);

rd_kafka_resp_err_t rd_kafka_DescribeConfigsRequest(
    rd_kafka_broker_t *rkb,
    const rd_list_t *configs /*(ConfigResource_t*)*/,
    rd_kafka_AdminOptions_t *options,
    char *errstr,
    size_t errstr_size,
    rd_kafka_replyq_t replyq,
    rd_kafka_resp_cb_t *resp_cb,
    void *opaque);

rd_kafka_resp_err_t
rd_kafka_DeleteGroupsRequest(rd_kafka_broker_t *rkb,
                             const rd_list_t *del_groups /*(DeleteGroup_t*)*/,
                             rd_kafka_AdminOptions_t *options,
                             char *errstr,
                             size_t errstr_size,
                             rd_kafka_replyq_t replyq,
                             rd_kafka_resp_cb_t *resp_cb,
                             void *opaque);

void rd_kafka_handle_InitProducerId(rd_kafka_t *rk,
                                    rd_kafka_broker_t *rkb,
                                    rd_kafka_resp_err_t err,
                                    rd_kafka_buf_t *rkbuf,
                                    rd_kafka_buf_t *request,
                                    void *opaque);

rd_kafka_resp_err_t
rd_kafka_InitProducerIdRequest(rd_kafka_broker_t *rkb,
                               const char *transactional_id,
                               int transaction_timeout_ms,
                               const rd_kafka_pid_t *current_pid,
                               char *errstr,
                               size_t errstr_size,
                               rd_kafka_replyq_t replyq,
                               rd_kafka_resp_cb_t *resp_cb,
                               void *opaque);

rd_kafka_resp_err_t
rd_kafka_AddPartitionsToTxnRequest(rd_kafka_broker_t *rkb,
                                   const char *transactional_id,
                                   rd_kafka_pid_t pid,
                                   const rd_kafka_toppar_tqhead_t *rktps,
                                   char *errstr,
                                   size_t errstr_size,
                                   rd_kafka_replyq_t replyq,
                                   rd_kafka_resp_cb_t *resp_cb,
                                   void *opaque);

void rd_kafka_handle_InitProducerId(rd_kafka_t *rk,
                                    rd_kafka_broker_t *rkb,
                                    rd_kafka_resp_err_t err,
                                    rd_kafka_buf_t *rkbuf,
                                    rd_kafka_buf_t *request,
                                    void *opaque);

rd_kafka_resp_err_t
rd_kafka_AddOffsetsToTxnRequest(rd_kafka_broker_t *rkb,
                                const char *transactional_id,
                                rd_kafka_pid_t pid,
                                const char *group_id,
                                char *errstr,
                                size_t errstr_size,
                                rd_kafka_replyq_t replyq,
                                rd_kafka_resp_cb_t *resp_cb,
                                void *opaque);

rd_kafka_resp_err_t rd_kafka_EndTxnRequest(rd_kafka_broker_t *rkb,
                                           const char *transactional_id,
                                           rd_kafka_pid_t pid,
                                           rd_bool_t committed,
                                           char *errstr,
                                           size_t errstr_size,
                                           rd_kafka_replyq_t replyq,
                                           rd_kafka_resp_cb_t *resp_cb,
                                           void *opaque);

int unittest_request(void);


rd_kafka_resp_err_t
rd_kafka_DeleteRecordsRequest(rd_kafka_broker_t *rkb,
                              /*(rd_topic_partition_list_t*)*/
                              const rd_list_t *offsets_list,
                              rd_kafka_AdminOptions_t *options,
                              char *errstr,
                              size_t errstr_size,
                              rd_kafka_replyq_t replyq,
                              rd_kafka_resp_cb_t *resp_cb,
                              void *opaque);

rd_kafka_resp_err_t
rd_kafka_CreateAclsRequest(rd_kafka_broker_t *rkb,
                           const rd_list_t *new_acls /*(AclBinding_t*)*/,
                           rd_kafka_AdminOptions_t *options,
                           char *errstr,
                           size_t errstr_size,
                           rd_kafka_replyq_t replyq,
                           rd_kafka_resp_cb_t *resp_cb,
                           void *opaque);

rd_kafka_resp_err_t
rd_kafka_DescribeAclsRequest(rd_kafka_broker_t *rkb,
                             const rd_list_t *acls /*(AclBinding*)*/,
                             rd_kafka_AdminOptions_t *options,
                             char *errstr,
                             size_t errstr_size,
                             rd_kafka_replyq_t replyq,
                             rd_kafka_resp_cb_t *resp_cb,
                             void *opaque);

rd_kafka_resp_err_t
rd_kafka_DeleteAclsRequest(rd_kafka_broker_t *rkb,
                           const rd_list_t *del_acls /*(AclBindingFilter*)*/,
                           rd_kafka_AdminOptions_t *options,
                           char *errstr,
                           size_t errstr_size,
                           rd_kafka_replyq_t replyq,
                           rd_kafka_resp_cb_t *resp_cb,
                           void *opaque);


#endif /* _RDKAFKA_REQUEST_H_ */

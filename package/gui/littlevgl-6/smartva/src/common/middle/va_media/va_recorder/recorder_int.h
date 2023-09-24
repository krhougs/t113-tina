#ifndef _RECORDER_INT_H_
#define _RECORDER_INT_H_

#include "Trecorder.h"
#include "dbList.h"

#define CHECK_NULL_POINTER(e)                                            \
		do {														\
			if (!(e))												\
			{														\
				printf("check (%s) failed.", #e);		   \
				return -1;											\
			}														\
		} while (0)


//#define PARTH_A  "/mnt/SDCARD/DCIMA"
//#define PARTH_B  "/mnt/SDCARD/DCIMB"
#define SENSOR_NUM 1

#define FILE_NAME_PREFIX  "AW_"
typedef struct {
	unsigned int width;
	unsigned int height;
}R_SIZE;

/*
   0: ���л�����ǰ����ͷ����
   1: ���л�����������ͷ����
   2:  ���л��أ���ʾǰ����ͷ
   3: ���л���, ��ʾ������ͷ
*/
typedef enum tag_PREVIEW_MODE_E{
	PREVIEW_HOST,
	PREVIEW_PIP,
	PREVIEW_
}__preview_mode_e;

typedef enum tag_RECORD_STATE{
	RECORD_UNINIT,
    RECORD_STOP,
	RECORD_START,
	RECORD_HALT,
}__record_state_e;

typedef enum tag_CAMERA_QUALITY{
    CAMERA_QUALITY_100,
    CAMERA_QUALITY_200,
    CAMERA_QUALITY_300,
    CAMERA_QUALITY_500,
    CAMERA_QUALITY_800,
}__camera_quality_e;

typedef enum tag_RECORD_QUALITY{
    RECORD_QUALITY_640_480,
    RECORD_QUALITY_1280_720,
    RECORD_QUALITY_1920_1080,
}__record_quality_e;

typedef enum tag_CYCLE_REC_TIME_E{
    CYCLE_REC_TIME_1_MIM,
    CYCLE_REC_TIME_2_MIM,
    CYCLE_REC_TIME_3_MIM,
    CYCLE_REC_TIME_5_MIM,
    CYCLE_REC_TIME_
}__cycle_rec_time_e;

typedef enum __RECORD_VID_WIN_RATIO_MODE
{
    RECORD_VID_WIN_BESTSHOW = 0x00,        /* ��ͼƬ����ı�����������������ʾ��ͼƬ������ */
    RECORD_VID_WIN_ORIGINAL,               /* ��ͼƬԭʼ��С�ڴ�������ʾ�������������     */
    RECORD_VID_WIN_FULLSCN,                /* �Դ��ڵı�������ͼƬ����������ʾ�����ܻ���� */
    RECORD_VID_WIN_CUTEDGE,                /* �ñ�ģʽ����srcFrame�����ٲõ����ºڱߣ��ñߺ���bestshowģʽ��ʾ         */
    RECORD_VID_WIN_NOTCARE,                /* ������ͼƬ��ʾ�������Ե�ǰ���õı���         */
    RECORD_VID_WIN_ORIG_CUTEDGE_FULLSCN,    /* ��ͼƬ����ı�����������������ʾ��ͼƬ����,ͼƬ�������ֲü���     */
    RECORD_VID_WIN_UNKNOWN
}record_vid_win_ratio_mode_t;

typedef struct tag_DV_CORE{
	//�ڲ���ֵ
	TrecorderHandle*       mTrecorder;			//����ͷ���
	__record_state_e	   record_sta;			// ¼���״̬
	R_SIZE				   cam_size;			//���շֱ���
	R_SIZE                 rec_size;			//¼��ֱ���
	unsigned int           rec_time_ms;			//¼������ļ�ʱ��,��λms
	pthread_mutex_t			mutex0;      //������ײ����
	pthread_mutex_t			mutex1;      //����¼����״̬
	//�ⲿ��ֵ
    TdispRect              show_rect;					// ��ʾ����
    __camera_quality_e     cam_quality_mode;	//��������
	__record_quality_e     rec_quality_mode;	//¼������
	R_SIZE				   source_size;			//��ƵԴ�ֱ���
	unsigned int           source_frate;		//��ƵԴ֡��
	__cycle_rec_time_e     cycle_rec_time;      //ѭ��¼���ʱ��
	unsigned int           frame_rate;			//֡��
	unsigned int		   video_bps;			//����
	unsigned int           mute_en;		    // 1 ���� 0 ������
	__preview_mode_e       pre_mode;
	int                    time_water_en;	// ʱ��ˮӡ����
	TCaptureConfig			phtoto_config;
}__dv_core_t;

typedef struct REC_MEDIA_INFO_T{
    TdispRect              show_rect;					// ����ʾ����
    record_vid_win_ratio_mode_t ratio_mode;					//��ʾģʽ
    __camera_quality_e     cam_quality_mode;	//��������
	__record_quality_e     rec_quality_mode;	//¼������
	R_SIZE				   source_size;			//��ƵԴ�ֱ���
	unsigned int		   source_frate;		//��ƵԴ֡��
	__cycle_rec_time_e     cycle_rec_time;      //ѭ��¼���ʱ��
	unsigned int           mute_en;			// 1 ���� 0 ������
	__preview_mode_e       pre_mode;
	int                    time_water_en;	// ʱ��ˮӡ����
}rec_media_info_t;

typedef struct
{
	__cycle_rec_time_e     cycle_rec_time;      //ѭ��¼���ʱ��
	unsigned int           mute_en;			// 1 ���� 0 ������
	int                    time_water_en;	// ʱ��ˮӡ����
}rec_media_part_info_t;


typedef enum recorder_cmd_t{
	CAMRERA_INIT_CMD,
	CAMRERA_EXIT_CMD,
	AUDIO_START_CMD,
	AUDIO_STOP_CMD,
	PREVIEW_START_CMD,
	PREVIEW_STOP_CMD,
	PREVIEW_DISPLAY_ENABLE_CMD,
	RECORDER_START_CMD,
	RECORDER_STOP_CMD,
	TAKE_PICTURE_CMD,
}recorder_cmd_t;

typedef struct rec_cmd_param_t{
	recorder_cmd_t cmd;
	int index;
	int param[2];
}rec_cmd_param_t;


typedef struct recorder_t
{
	db_list_t*			queue_head;
	pthread_t			id;
	__dv_core_t			dv_core[SENSOR_NUM];
	char				*mount_path;
	char				photo_path[128];
	char				video_path[128];
	char				audio_path[128];

	pthread_mutex_t   cond_mutex;
	pthread_cond_t	  cond;

	int				wait_flag;
}recorder_t;

recorder_t *recorder_pthread_create(void);
int recorder_pthread_destory(recorder_t *recorder);
int recorder_send_cmd(recorder_t *recorder, recorder_cmd_t cmd, int index, int param);
int recorder_set_sensor_info(recorder_t *recorder, int index);
int recorder_set_mount_path(recorder_t *recorder, char *path);
int get_recorder_path(recorder_t *recorder, int index, int flag);
__record_state_e recorder_get_status(recorder_t *recorder, int index);

#endif

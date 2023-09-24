#ifndef __MOC_EXPLORER_H__
#define __MOC_EXPLORER_H__
#include "FileList.h"
#include "va_image.h"

typedef  struct
{
	file_list_t*		top_file_list;			//top filelist,��??��2?????
	file_list_t*		cur_file_list;			//current filelist,�̡�?��????
	file_item_t*		file_item;				//�̡�?��?1��?item
	int		CurIsEmpty;				//�̡�?��?1��?item
}explorer_list_t;

typedef struct tag_rat_ctrl{
	HRAT  handle;				//???t???��??����
	int32_t index;				//�̡�?��???t?�¨�yo?
	int32_t total;				//???t������y
	rat_media_type_t media_type;//???��???t��?����D��
	char SearchPath[256];//???��???t��?����D��
}rat_ctrl_t;

typedef enum {
	EXPLORER_IMAGE_AUDIO = 0,
	EXPLORER_IMAGE_VIDEO,
	EXPLORER_IMAGE_PICTURE,
	EXPLORER_IMAGE_FIRMWARE,
	EXPLORER_IMAGE_FOLDER,
	EXPLORER_IMAGE_TEXT,
	EXPLORER_IMAGE_USB,
	EXPLORER_IMAGE_SD,
	EXPLORER_IMAGE_MORE,
	EXPLORER_IMAGE_UNKOWN,
	EXPLORER_IMAGE_NUM_MAX
}explorer_image_t;

#define EXPLORER_IMAGE_AUDIO_PATH LV_IMAGE_PATH"explorer_audio.png"
#define EXPLORER_IMAGE_VIDEO_PATH LV_IMAGE_PATH"explorer_video.png"
#define EXPLORER_IMAGE_PICTURE_PATH LV_IMAGE_PATH"explorer_picture.png"
#define EXPLORER_IMAGE_FIRMWARE_PATH LV_IMAGE_PATH"explorer_firmware.png"
#define EXPLORER_IMAGE_FOLDER_PATH LV_IMAGE_PATH"explorer_folder.png"
#define EXPLORER_IMAGE_TEXT_PATH LV_IMAGE_PATH"explorer_text.png"
#define EXPLORER_IMAGE_USB_PATH LV_IMAGE_PATH"explorer_usb.png"
#define EXPLORER_IMAGE_SD_PATH LV_IMAGE_PATH"explorer_sd.png"
#define EXPLORER_IMAGE_MORE_PATH LV_IMAGE_PATH"explorer_more.png"
#define EXPLORER_IMAGE_UNKOWN_PATH LV_IMAGE_PATH"explorer_unkown.png"

#define EXPLORER_LIST_PERLOAD_ITEM_NUM	(8)
#define EXPLORER_LIST_TASKLOAD_ITEM_NUM	(8)
#endif /*__MOC_EXPLORER_H__*/

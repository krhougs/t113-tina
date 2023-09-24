#ifndef __BS_WIDGET_H__
#define __BS_WIDGET_H__

#ifdef __cplusplus
extern "C" {
#endif

/**********************
 *      includes
 **********************/
#include "lvgl.h"
#include "common.h"

/*
************************************************************************************
*                                     background
************************************************************************************
*/
int background_photo_init(void);
int background_photo_uninit(void);
int update_background_photo(int id);
void* get_background_photo(void);


/*
************************************************************************************
*                                     key group
************************************************************************************
*/
lv_group_t* key_group_create(void);
void key_group_del();
lv_group_t* get_key_group(void);


/*
************************************************************************************
*                                     font & multi-language
************************************************************************************
*/
#define CONFIG_FONT_ENABLE 0
#if CONFIG_FONT_ENABLE
/* ��?��?1������*/
typedef struct {
	lv_font_t *msyh_16;		/* ?�騨��??o�� 16o?��?��?*/
	lv_font_t *msyh_20;		/* ?�騨��??o�� 20o?��?��?*/
							/* ��??����D������?��*/
}font_lib_t;

void font_init(void);
void font_uninit(void);
/* ��??��??��?font_lib ����??��??oD����a��?��?��?*/
font_lib_t *get_font_lib(void);

#define TEXT_MAX 500	/* ��??����D������?��*/

/* ?����???1������*/
#define LANG_FILE_CN_S	"/usr/res/font/ChineseS.bin"
#define LANG_FILE_EN	"/usr/res/font/English.bin"
#define LANG_FILE_CN_T	"/usr/res/font/zh-CN_T.bin"
#define LANG_FILE_JPN	"/usr/res/font/jpn.bin"

#if 0
typedef enum {
	HOME_START = 10,		/* home3??��?e��???��?id*/
	SETTING_START = 60,
	MOVIE_START = 113,      /* movie3??��?e��???��?id*/
	MUSIC_START = 144,		/* music3??��?e��???��?id*/
	TEXT_MAX = 500,
}lang_text_id;
#endif
typedef enum {
	LANG_CN_S = 0,		/* ���ļ���*/
	LANG_EN = 1,		/* Ӣ��*/
	LANG_CN_T = 2,		/* ���ķ���*/
	LANG_JPN = 3,		/* ����*/
	LANG_ERR			/* �û��������*/
}language_t;

typedef struct {
	language_t lang;
	char *text_buff;
	char *text[TEXT_MAX];
}lang_info_t;

void lang_and_text_init(language_t lang);
void lang_and_text_uninit(void);
void lang_and_text_update(language_t lang);
language_t get_language(void);
const char* get_text_by_id(int id);
#endif
void list_label_set_text(lv_obj_t * list, lv_style_t *style, unsigned int text[]);
void app_param_effect(int reset);
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /*__UI_TEST_HBAR_H__*/

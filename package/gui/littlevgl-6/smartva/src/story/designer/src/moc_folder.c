/**********************
 *      includes
 **********************/
#include "moc_folder.h"
#include "ui_folder.h"
#include "lvgl.h"
#include "page.h"
#include "ui_resource.h"


/**********************
 *       variables
 **********************/
typedef struct
{
	folder_ui_t ui;
} folder_para_t;
static folder_para_t para;


/**********************
 *  functions
 **********************/
static void back_btn_event(lv_obj_t * btn, lv_event_t event)
{
	if (event == LV_EVENT_CLICKED)
	{
		//destory_page(PAGE_FOLDER);
		//create_page(PAGE_HOME);
		switch_page(PAGE_FOLDER, PAGE_HOME);
	}
}

static int create_folder(void)
{
	com_info("#######\n");
	para.ui.cont = lv_cont_create(lv_scr_act(), NULL);
	lv_obj_set_size(para.ui.cont, LV_HOR_RES_MAX, LV_VER_RES_MAX);
	static lv_style_t cont_style;
	lv_style_copy(&cont_style, &lv_style_plain);
	cont_style.body.main_color = LV_COLOR_BLUE;
	cont_style.body.grad_color = LV_COLOR_BLUE;
	lv_cont_set_style(para.ui.cont, LV_CONT_STYLE_MAIN, &cont_style);
	lv_cont_set_layout(para.ui.cont, LV_LAYOUT_OFF);
	lv_cont_set_fit(para.ui.cont, LV_FIT_NONE);

	static lv_style_t back_btn_style;
	lv_style_copy(&back_btn_style, &lv_style_pretty);
	back_btn_style.text.font = &lv_font_roboto_28;
	lv_obj_t *back_btn = lv_btn_create(para.ui.cont, NULL);
	lv_obj_align(back_btn, para.ui.cont, LV_ALIGN_IN_TOP_LEFT, 0, 0);
	lv_obj_t *back_lable = lv_label_create(back_btn, NULL);
	lv_label_set_text(back_lable, LV_SYMBOL_LEFT);
	lv_obj_set_event_cb(back_btn, back_btn_event);
	lv_btn_set_style(back_btn, LV_BTN_STYLE_REL, &back_btn_style);
	lv_btn_set_style(back_btn, LV_BTN_STYLE_PR, &back_btn_style);

	folder_auto_ui_create(&para.ui);
	return 0;
}

static int destory_folder(void)
{
	com_info("#######\n");
	folder_auto_ui_destory(&para.ui);
	lv_obj_del(para.ui.cont);

	return 0;
}

static int show_folder(void)
{
	lv_obj_set_hidden(para.ui.cont, 0);

	return 0;
}

static int hide_folder(void)
{
	lv_obj_set_hidden(para.ui.cont, 1);

	return 0;
}

static int msg_proc_folder(MsgDataInfo *msg)
{
	return 0;
}

static page_interface_t page_folder =
{
	.ops =
	{
		create_folder,
		destory_folder,
		show_folder,
		hide_folder,
		msg_proc_folder,
	},
	.info =
	{
		.id         = PAGE_FOLDER,
		.user_data  = NULL
	}
};

void REGISTER_PAGE_FOLDER(void)
{
	reg_page(&page_folder);
}

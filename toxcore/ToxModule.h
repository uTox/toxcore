#ifndef TOX_MODULE_H
#define TOX_MODULE_H

typedef struct ToxModule {
    void *mod_data;

    void (*mod_iterate)(void *mod_data, void *userdata);
    void (*mod_raze)(void *mod_data);
} ToxModule;


#endif // TOX_MODULE_H

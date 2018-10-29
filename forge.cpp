#include "forge.h"
#include "ui_forge.h"

Forge::Forge(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Forge)
{
    ui->setupUi(this);
}

Forge::~Forge()
{
    delete ui;
}

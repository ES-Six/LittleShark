#ifndef FORGE_H
#define FORGE_H

#include <QWidget>

namespace Ui {
class Forge;
}

class Forge : public QWidget
{
    Q_OBJECT

public:
    explicit Forge(QWidget *parent = 0);
    ~Forge();

private:
    Ui::Forge *ui;
};

#endif // FORGE_H

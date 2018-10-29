#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include "home.h"
#include "capture.h"
#include "forge.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_actionLive_capture_triggered();

    void on_actionLoad_from_file_triggered();

    void on_actionSave_to_file_triggered();

    void on_actionPacket_forging_triggered();

    void on_actionExit_triggered();

private:
    void deleteAllTheThings();

    Ui::MainWindow *ui;
    Home *homeWidget = nullptr;
    Capture *captureWidget = nullptr;
    Forge *forgeWidget = nullptr;
};

#endif // MAINWINDOW_H

#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();
    void addMoney(int num);
    void subMoney(int num);
    void checkMoney(int num);
private slots:
    void on_Button500_clicked();

    void on_Button100_clicked();

    void on_Button50_clicked();

    void on_Button10_clicked();

    void on_Coffee_clicked();

    void on_Tea_clicked();

    void on_Yul_clicked();

    void on_RestButton_clicked();

private:
    Ui::Widget *ui;


};

#endif // WIDGET_H

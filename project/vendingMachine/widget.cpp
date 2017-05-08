#include "widget.h"
#include "ui_widget.h"
#include <QMessageBox>

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
       curMoney=ui->lcdNumber->intValue();
        checkMoney();
}

Widget::~Widget()
{
    delete ui;
}



void Widget::addMoney(int num)
{
    ui->lcdNumber->display(QString::number(curMoney+=num));
}

void Widget::subMoney(int num)
{
    ui->lcdNumber->display(QString::number(curMoney-=num));
}

void Widget::checkMoney()
{
     ui->Tea->setEnabled(!(curMoney<100));
     ui->Yul->setEnabled(!(curMoney<250));
     ui->Coffee->setEnabled(!(curMoney<200));
}

void Widget::on_Button500_clicked()
{
    addMoney(500);
    checkMoney();
}

void Widget::on_Button100_clicked()
{
    addMoney(100);
    checkMoney();
}

void Widget::on_Button50_clicked()
{
    addMoney(50);
    checkMoney();
}

void Widget::on_Button10_clicked()
{
    addMoney(10);
    checkMoney();
}

void Widget::on_Coffee_clicked()
{

    subMoney(200);
    checkMoney();

}

void Widget::on_Tea_clicked()
{
    subMoney(100);
    checkMoney();

}

void Widget::on_Yul_clicked()
{
        subMoney(250);

        checkMoney();
}

void Widget::on_RestButton_clicked()
{
    int credit500=curMoney/500;
    curMoney%=500;
    int credit100=curMoney/100;
    curMoney%=100;
    int credit50=curMoney/50;
    curMoney%=50;
    int credit10=curMoney/10;

    curMoney=0;
    checkMoney();

    QMessageBox qMessageBox;
    QString infor500="credit 500 " + QString::number(credit500)+ " left \n";
    infor500+="credit 100 " + QString::number(credit100)+ " left \n";
    infor500+="credit 50 " + QString::number(credit50)+ " left \n";
    infor500+="credit 10 " + QString::number(credit10)+ " left \n";
    qMessageBox.setInformativeText("credit 100 " + QString::number(credit100));
    ui->lcdNumber->display(QString::number(curMoney));
    qMessageBox.information(this,"Information",infor500,QMessageBox::Yes);
}


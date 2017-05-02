#include "widget.h"
#include "ui_widget.h"
#include <QMessageBox>

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
        ui->Coffee->setEnabled(false);
            ui->Tea->setEnabled(false);
                ui->Yul->setEnabled(false);

}

Widget::~Widget()
{
    delete ui;
}



void Widget::addMoney(int num)
{
    ui->lineEdit->setText(QString::number(ui->lineEdit->text().toInt()+num));
}

void Widget::subMoney(int num)
{
    ui->lineEdit->setText(QString::number(ui->lineEdit->text().toInt()-num));
}

void Widget::checkMoney(int num)
{
     ui->Tea->setEnabled(!(num<100));
     ui->Yul->setEnabled(!(num<250));
     ui->Coffee->setEnabled(!(num<200));
}

void Widget::on_Button500_clicked()
{
    addMoney(500);
    checkMoney(ui->lineEdit->text().toInt());
}

void Widget::on_Button100_clicked()
{
    addMoney(100);
    checkMoney(ui->lineEdit->text().toInt());
}

void Widget::on_Button50_clicked()
{
    addMoney(50);
    checkMoney(ui->lineEdit->text().toInt());
}

void Widget::on_Button10_clicked()
{
    addMoney(10);
    checkMoney(ui->lineEdit->text().toInt());
}

void Widget::on_Coffee_clicked()
{

    subMoney(200);
    checkMoney(ui->lineEdit->text().toInt());

}

void Widget::on_Tea_clicked()
{
    subMoney(100);
    checkMoney(ui->lineEdit->text().toInt());

}

void Widget::on_Yul_clicked()
{
        subMoney(250);

        checkMoney(ui->lineEdit->text().toInt());
}

void Widget::on_RestButton_clicked()
{
    int money=ui->lineEdit->text().toInt();
    int credit500=money/500;
    money=money %500;
    int credit100=money/100;
    money=money %100;
    int credit50=money/50;
    money=money %50;
    int credit10=money/10;

    ui->lineEdit->setText("0");
    //disalbe all menus
    ui->Coffee->setEnabled(false);
    ui->Tea->setEnabled(false);
    ui->Yul->setEnabled(false);

    QMessageBox qMessageBox;
    QString infor500="credit 500 " + QString::number(credit500)+ " left \n";
    infor500+="credit 100 " + QString::number(credit100)+ " left \n";
    infor500+="credit 50 " + QString::number(credit50)+ " left \n";
    infor500+="credit 10 " + QString::number(credit10)+ " left \n";
    qMessageBox.setInformativeText("credit 100 " + QString::number(credit100));
  //  qMessageBox.setStandardButtons(QMessageBox::Yes);
    qMessageBox.information(this,"Information",infor500,QMessageBox::Yes);
}


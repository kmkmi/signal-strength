#pragma once

#include <cstdint>
#include <cstring>
#include <string>


#define MANAGEMENT_FRAME 0b00
#define BEACON_FRAME 0b1000
#define PROBE_RESPONSE 0b0101
#define DATA_FRAME 0b10
#define NULL_SUBTYPE 0b0100
#define QOS_NULL 0b1100

typedef struct Mac final {
    static const int SIZE = 6;
    uint8_t mac_[SIZE];

    //
    // constructor
    //
    Mac() {}
    Mac(const uint8_t* r) { memcpy(this->mac_, r, SIZE); }
    Mac(const std::string r){
        unsigned int a, b, c, d, e, f;
        int res = sscanf(r.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X", &a, &b, &c, &d, &e, &f);
        if (res != SIZE) {
            fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
            return;
        }
        mac_[0] = a;
        mac_[1] = b;
        mac_[2] = c;
        mac_[3] = d;
        mac_[4] = e;
        mac_[5] = f;
    };


    // casting operator
    //
    operator uint8_t*() const { return const_cast<uint8_t*>(mac_); } // default
    explicit operator std::string() const{
        char buf[32]; // enough size
        sprintf(buf, "%02x:%02X:%02X:%02X:%02X:%02X",
                mac_[0],
                mac_[1],
                mac_[2],
                mac_[3],
                mac_[4],
                mac_[5]);
        return std::string(buf);
    };

    //
    // comparison operator
    //

    bool operator < (const Mac& r) const
    {
        for (int i=0; i<6; i++){
            if(mac_[i] == r.mac_[i])
                continue;
            return mac_[i] > r.mac_[i];
        }
        return false;
    };

    bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) == 0; };
    bool operator != (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) != 0; };



} Mac;




#pragma pack(push, 1)

typedef struct Present_Flags{
    uint8_t tsft:1;
    uint8_t flags:1;
    uint8_t rate:1;
    uint8_t channel:1;
    uint8_t fhss:1;
    uint8_t dbm_antenna_sig:1;


    uint8_t extra1:2;
    uint8_t extra2[2];
    uint8_t extra3:7;

    uint8_t ext:1;
}Present_Flags;

typedef struct Rtap{

    uint8_t header_revision;
    uint8_t header_pad;
    uint16_t header_length;
    Present_Flags present_flags[2];

} Rtap;




typedef struct Frame_Control_Field{
    uint8_t version:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t flags;

    bool isBeaconFrame(){
        if (this->type == MANAGEMENT_FRAME && this->subtype == BEACON_FRAME)
            return true;

        return false;
    }

    bool isProbeResponse(){
        if (this->type == MANAGEMENT_FRAME && this->subtype == PROBE_RESPONSE)
            return true;

        return false;
    }


    bool isDataFrame(){
        if (this->type == DATA_FRAME && this->subtype != NULL_SUBTYPE && this->subtype != QOS_NULL )
            return true;

        return false;
    }


}Frame_Control_Field;

//Beacon Frame and Probe Response Can Use This Structure.
typedef struct Beacon_Frame{
    Frame_Control_Field frame_control_field;
    uint16_t duration;
    Mac mac1;
    Mac mac2;
    Mac mac3;
    uint16_t sequence_number:12;
    uint16_t fragment_number:4;
}Beacon_Frame;

typedef struct Data_Frame{
    Frame_Control_Field frame_control_field;
    uint16_t duration;
    Mac mac1;
    Mac mac2;

}DATA_Frame;

typedef struct Dot11_wlan{
    uint8_t fixed_parameters[12];
    uint8_t tag_number;
    uint8_t tag_length;
    char ssid[32];

    void getSSID(char* buf){

        strncpy(buf, ssid,(size_t)tag_length );
        buf[(size_t)tag_length] = '\0';
    }
}Dot11_wlan;



typedef struct Ap_value{
    uint8_t Beacons;
    uint8_t nData;
    char enc[4];
    char ESSID[33];
    unsigned int pwr;

    Ap_value(uint8_t Beacons,
             uint8_t nData,
             char* enc,
             char* ESSID,
             int pwr){
        this->Beacons = Beacons;
        this->nData = nData;
        strncpy((char*)&this->enc, enc, strlen(enc)+1);
        strncpy((char*)&this->ESSID, ESSID, strlen(ESSID)+1);
        this->pwr = pwr;
    };

}Ap_value;
#pragma pack(pop)



#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <unistd.h>
#include <QtCharts>
#include <QComboBox>




QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE



class MainWindow : public QMainWindow
{
    Q_OBJECT



public:
    MainWindow(QWidget *parent = nullptr)
        : QMainWindow(parent)
    {

        series = new QLineSeries();
        series->setPointLabelsVisible(true);
        series->setPointLabelsColor(Qt::black);
        series->setPointLabelsFormat("@yPoint");


        chart= new QChart();
        chart->legend()->hide();
        chart->addSeries(series);
        chart->createDefaultAxes();
        chart->setTitle("Signal PWR(dBm)");


        chartView = new QChartView(chart);
        chartView->setRenderHint(QPainter::Antialiasing);
        this->setCentralWidget(chartView);
        this->resize(800, 600);

        combo = new QComboBox(this);
        combo->move(10, 10);



        connect(combo, SIGNAL(activated(int)), this, SLOT(selectComboBox(int)));
        connect(this, SIGNAL(looped(QList<int>)), this, SLOT(refresh(QList<int>)));

        this->show();

    };
    ~MainWindow(){};

    QComboBox* combo;
    Mac selected = Mac("00:00:00:00:00:00");
    std::map<Mac,std::pair<int,int>> MaxMin;

signals:
    void looped(QList<int> );

private slots:
    void refresh(QList<int> powerlist){

        chart->removeSeries(series);
        series->clear();
        chart->axisX()->setRange(0, powerlist.size());
        for(int i = 0; i<  powerlist.size();i++){
            series->append(i,  powerlist[i]);
            if(powerlist[i]>MaxMin[selected].first){
                MaxMin[selected].first =powerlist[i];
            }
            if(powerlist[i]<MaxMin[selected].second){
                MaxMin[selected].second =powerlist[i];
            }

        }
        chart->axisY()->setRange(MaxMin[selected].second, MaxMin[selected].first);
        chart->addSeries(series);


        this->repaint();
    };
    void selectComboBox(int _index)
    {
        selected  = Mac(combo->currentText().toStdString());

    };

private:
    Ui::MainWindow *ui;
    QLineSeries *series;
    QChart *chart;
    QChartView *chartView;


};


#endif // MAINWINDOW_H



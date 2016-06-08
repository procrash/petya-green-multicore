/*
 * MainApplication.cpp
 *
 *  Created on: 03.06.2016
 *      Author: wolfgangmeyerle
 */

#include "MainApplication.h"
#include "MainAppFrame.h"
#include "wxImagePanel.h"

#include <wx/wx.h>


//	EVT_SIZE(MainAppFrame::OnSize)


wxBEGIN_EVENT_TABLE(MainAppFrame, wxFrame)
    EVT_MENU(ID_Hello,   MainAppFrame::OnHello)
    EVT_MENU(wxID_EXIT,  MainAppFrame::OnExit)
    EVT_MENU(wxID_ABOUT, MainAppFrame::OnAbout)
	EVT_SIZE(MainAppFrame::OnSize)
	EVT_BUTTON(ButtonChooseDiskDump, MainAppFrame::OnOpenDiskDumpFile)
	EVT_BUTTON(ButtonFindGPUParameters, MainAppFrame::OnFindGPUParameters)
	EVT_COMBOBOX(ComboBoxSourceChoice, MainAppFrame::OnComboBoxSourceChanged)
	EVT_BUTTON(ButtonStartCalculation, MainAppFrame::OnStartCalculation)
wxEND_EVENT_TABLE()
wxIMPLEMENT_APP(MainApplication);



bool MainApplication::OnInit()
{
	int width = 540;
    MainAppFrame *frame = new MainAppFrame( "Petya Green GPU Decryptor", wxPoint(50, 50), wxSize(width, 630) );
    frame->SetMinSize(wxSize(width,630));
    frame->Show( true );
    return true;
}






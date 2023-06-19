import sys
from PySide6 import QtWidgets

from AES.aes_encrypt import AES


class MyWidget(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setWindowTitle("AES 加解密")
        self.setFixedSize(400, 200)
        self.setup_ui()
        self.echo()

    def setup_ui(self) -> None:
        key_label = QtWidgets.QLabel("Key:")
        data_label = QtWidgets.QLabel("Data:")
        output_label = QtWidgets.QLabel("Output:")

        self.key_edit = QtWidgets.QLineEdit()
        self.data_edit = QtWidgets.QLineEdit()
        self.output_edit = QtWidgets.QLineEdit()

        self.encrypt_button = QtWidgets.QPushButton("Encrypt")
        self.decrypt_button = QtWidgets.QPushButton("Decrypt")

        form_layout = QtWidgets.QFormLayout()
        form_layout.addRow(key_label, self.key_edit)
        form_layout.addRow(data_label, self.data_edit)
        form_layout.addRow(output_label, self.output_edit)

        main_layout = QtWidgets.QVBoxLayout()
        main_layout.addLayout(form_layout)
        main_layout.addWidget(self.encrypt_button)
        main_layout.addWidget(self.decrypt_button)

        self.output_edit.setReadOnly(True)
        # self.output_edit.setClearButtonEnabled(True)

        self.setLayout(main_layout)


    def echo(self) -> None:
        self.key_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
        self.data_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)

        def encrypt():
            key = self.key_edit.text()
            data = self.data_edit.text()
            key = 'Thats my Kung Fu'
            data = 'Two One Nine Two'

            aes = AES(key, data)
            aes.encrypt()

            output_text = ' '.join([hex(num)[2:].zfill(2) for num in aes.output_matrix])
            self.output_edit.setText(output_text)

        def decrypt():
            key = self.key_edit.text()
            data = self.data_edit.text()
            key = 'Thats my Kung Fu'
            data = '29c3505f571420f6402299b31a02d73a'

            aes = AES(key, data)
            aes.decrypt()

            output_text = ' '.join([hex(num)[2:].zfill(2) for num in aes.output_matrix])
            self.output_edit.setText(output_text)

        self.encrypt_button.clicked.connect(encrypt)
        self.decrypt_button.clicked.connect(decrypt)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MyWidget()
    window.show()
    sys.exit(app.exec())

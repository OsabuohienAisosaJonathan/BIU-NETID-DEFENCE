import os

class FileSystem():

    def getRoot(self):
        root = os.path.dirname(os.path.abspath(__file__))
        return root

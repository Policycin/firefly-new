from chatterbot import ChatBot
from pymongo import MongoClient
from config import DevelopmentConfig

condev = DevelopmentConfig()
mongoIP = condev.MONGOIP
mongoPort = condev.MONGOPORT
db = MongoClient(mongoIP, port=mongoPort)
db = db.FireFly
mongoDbName = "FireFly"

# bot.logic.get_adapters()[1].confidence_threshold = 0.1 # 可以设置这个值。

bot = ChatBot(
    '人工智能',  # 名称
    read_only=True,
    storage_adapter='chatterbot.storage.MongoDatabaseAdapter',
    # 存储适配器 chatterbot.storage.MongoDatabaseAdapter   chatterbot.storage.SQLStorageAdapter
    database=mongoDbName,
    database_uri="mongodb://" + mongoIP + ":" + str(mongoPort) + "/",
    # input_adapter="chatterbot.input.TerminalAdapter",#输入适配器
    # output_adapter="chatterbot.output.TerminalAdapter",#输出适配器
    logic_adapters=[
        {
            'import_path': 'chatterbot.logic.BestMatch'  # chatterbot.logic.BestMatch MyLogicAdapter.MyLogicAdapter
            # "statement_comparison_function": "chatterbot.comparisons.levenshtein_distance",
            # "response_selection_method": "chatterbot.response_selection.get_first_response"
        },
        {
            'import_path': 'chatterbot.logic.LowConfidenceAdapter',
            'threshold': 0.45,
            'default_response': '对不起这个问题正在学习中20180308'
        }
    ],
    # filters=['chatterbot.filters.RepetitiveResponseFilter' ],
    # input_adapter="chatterbot.input.VariableInputTypeAdapter",
    # output_adapter="chatterbot.output.TerminalAdapter",
    # trainer='chatterbot.trainers.ListTrainer'
    # trainer='chatterbot.trainers.ChatterBotCorpusTrainer'

)
'''
'''
# bot.trainer.export_for_training('./my_export.json')

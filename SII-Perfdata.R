# ###############################
# cProfile output analysis
# Mike Libassi
# Jan 2015
#
# ################################

# Mongo db connections IF needed 
# library(devtools)
# library(rmongodb)
# mongo <- mongo.create()
# # List local dbs
# if(mongo.is.connected(mongo) == TRUE) {
#   mongo.get.databases(mongo)
# }
# 
# if(mongo.is.connected(mongo) == TRUE) {
#   db <- "prefdata"
#   mongo.get.database.collections(mongo, db)
# }
# 
# coll <- "prefdata.prefdata"
# 
# if(mongo.is.connected(mongo) == TRUE) {
#   help("mongo.count")
#   mongo.count(mongo, coll)
# }
# fpdata <- mongo.find.one(mongo, coll)
# fpdata
# ############### End Mongo stuff ################


# Turn off scinot
options(scipen=999)

# ############### Library loading ################

library(lattice)
library(grid)
library(ggplot2)
library(graph)
library (plyr)

# ################ Functions #####################

# Trim blanks
trim <- function (x) gsub("^\\s+|\\s+$", "", x)
clearspace <- function(x) gsub("^[[:space:]]+|[[:space:]]+$", "", x) 

# ################# End functions ##################

whitespace <- " \t\n\r\v\f"

# Set WD
dir <- '/Users/mike/Downloads/temp test data/'
setwd(dir)



## Files  
difffile <- 'test1-diffs-test1.csvscrubbed.csv'
stkdiffin <- 'test1-stackdiff-test1.csvscrubbed.csv'



diffsdata <- read.csv2(infile, fill = TRUE, sep = ",", header = TRUE, comment.char = "", skip = 3)
stkdiffdata <- read.csv2(stkdiffin, fill = TRUE, sep = ",", header = TRUE, comment.char = "", skip = 3)


# Set to csvdata for analysis 
csvdata <- diffsdata
csvdata <- stkdiffdata



# ################# take a infile from above #########################################

#Trim text
csvdata$filename.lineno.function. <- trim(csvdata$filename.lineno.function.)

# Factor function col
csvdata$filename.lineno.function. <- as.factor(csvdata$filename.lineno.function.)

#Convert to numeric
csvdata$tottime <- as.numeric(as.character(csvdata$tottime))
csvdata$percall <- as.numeric(as.character(csvdata$percall))
csvdata$cumtime <- as.numeric(as.character(csvdata$cumtime))
csvdata$percall.1 <- as.numeric(as.character(csvdata$percall.1))

# Mean numcalls and cumtime
smryncalls <- ddply(csvdata, .var = c("filename.lineno.function."), 
                    summarize, meanncall = mean(ncalls), meanct = mean(cumtime),
                    meantt = mean(tottime))

# Sort by number of calls  
smryncalls_sort <- smryncalls[order(-smryncalls$meanncall),]

# top 10 calls from sort 
top10 <- smryncalls_sort[1:10,]

# Sumary data 
summary(top10$meanncall)




# ############# Graphs ##########################
# http://www.statmethods.net/graphs/creating.html
# 
# Device reset
dev.off()
# ################################################
#
hist(top10$meanncall)
grid()

# Not too useful
histogram(~ top10$meanct | top10$filename.lineno.function., xlab = "Time by Function")
grid()

boxplot(top10$meanncall ~ top10$filename.lineno.function., data = top10,
        xlab = "Function", main = "SII Calls by Function", col = "red", cex.axis = 0.75)

# Mean numcalls and cumtime
smry <- ddply(csvdata, .var = c("filename.lineno.function."), 
              summarize, meanncall = mean(ncalls), meanct = mean(cumtime))

# This may work if I can get function name in
barplot(top10$meanncall, 
        main="Function Calls", xlab="Number of Calls")

# Dynamic charts
library(rCharts)
library(base64enc)

n1 <- nPlot(meanncall ~ meantt, group = "filename.lineno.function.", 
            data = top10, type = "multiBarChart")

n1$save('chart1.html', standalone = TRUE)





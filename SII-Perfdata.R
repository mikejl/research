# #######################################
# Mike Libassi
# SII-Perfdata.R
# R file for data analsyis
# from csv output of SII.py
#
# ############################################

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
#library(Cairo)


# ################ Functions #####################

# Trim blanks
trim <- function (x) gsub("^\\s+|\\s+$", "", x)
clearspace <- function(x) gsub("^[[:space:]]+|[[:space:]]+$", "", x) 

# ################# End functions ##################

whitespace <- " \t\n\r\v\f"

# ################# Pull from csv ##################
# Need to:
#   1. remove first three rows
#   2. fix last columns (merge and remove spaces)
#   3. Sort mu ncalls 
#   4. then save as <name>-scrib.csv

bolsfpt1file <- '/Users/mike/Downloads/localhost-boolsfp-test1-scrub.csv'
bolsfpt1 <- read.csv2(bolsfpt1file, fill = TRUE, sep = ",", header = TRUE, comment.char = "")

csvdata <- bolsfpt1

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






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


# ################# End functions ##################

# ################# Pull from csv ##################
csvfile <- '/Users/mike/Documents/output.csv'
csvdata <- read.csv2(csvfile, fill = TRUE, skip = 3, sep = ",", header = TRUE, comment.char = "\'")

##TODO .. fix truncating data on import.  

#Trim text
#csvdata$filename.lineno.function. <- trim(csvdata$filename.lineno.function.)


# Factor function col
csvdata$filename.lineno.function. <- as.factor(csvdata$filename.lineno.function.)

#Convert to numeric
csvdata$tottime <- as.numeric(as.character(csvdata$tottime))
csvdata$percall <- as.numeric(as.character(csvdata$percall))
csvdata$cumtime <- as.numeric(as.character(csvdata$cumtime))
csvdata$percall.1 <- as.numeric(as.character(csvdata$percall.1))

#df <- data.frame(matrix(unlist(csvdata),byrow=T))

#df2 <- ldply (csvdata, data.frame)

# Sort by number of calls  ## Cuts off filename.lineno.function text.
csvdata_sort <- csvdata[order(-csvdata$ncalls),]


# Mean numcalls and cumtime
smryncalls <- ddply(csvdata, .var = c("filename.lineno.function."), 
                    summarize, meanncall = mean(ncalls), meanct = mean(cumtime),
                    meantt = mean(tottime))
# Sort smryncalls

# top 10 calls from sort 
top20 <- csvdata_sort[1:20,]

# Graphs
# http://www.statmethods.net/graphs/creating.html
# 
# Device reset
dev.off()

#
hist(csvdata$ncalls)
grid()

histogram(~ top20$cumtime | top20$filename.lineno.function., xlab = "Time by Function")
grid()

boxplot(csvdata$ncalls ~ csvdata$filename.lineno.function., data = csvdata,
        xlab = "Function", main = "SII Calls by Function", col = "red", cex.axis = 0.75)

# Mean numcalls and cumtime
smryncalls <- ddply(csvdata, .var = c("filename.lineno.function."), summarize, meanncall = mean(ncalls), meanct = mean(cumtime))

plot(smryncalls)

boxplot(smryncalls$meanncall ~ smryncalls$filename.lineno.function., data = smryncalls,
        xlab = "Function", main = "SII Calls by Function", col = "red", cex.axis = 0.75)

histogram(~ smryncalls$meanncall)
grid()


barplot(smryncalls$meanncall, main="Function Calls", xlab="Number of Calls")


# Just the data
boxplot(csvdata$ncalls ~ csvdata$filename.lineno.function., data = csvdata,
        xlab = "Function", main = "SII Calls by Function", plot = FALSE)




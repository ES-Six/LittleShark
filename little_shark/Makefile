CC	:= g++

RM	:= rm -rf

LDFLAGS	+= 

CFLAGS	+= -Iheader

SRCS	:= $(shell find src -type f -name "*.cpp")
SRCS	+= main.cpp

OBJS	:= $(SRCS:.cpp=.o)

NAME	:= littleshark

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) -o $(NAME) $(OBJS) $(LDFLAGS)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all re clean fclean
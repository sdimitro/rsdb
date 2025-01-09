#include <stdio.h>
#include <stdint.h>
#include <assert.h>

typedef struct mtype {
	uint64_t m_x;
	long m_long;
} mtype_t;

typedef uint64_t ID;

char *HELP = "EXAMPLE STRING";

uint64_t
addition(mtype_t m)
{
	printf("Called addition!\n");
	printf("%s\n", HELP);
	uint64_t y = m.m_long + 1;
	y++;
	assert(0);
	return m.m_x + y++;
}

uint64_t
addition_rec(struct mtype m, int rec)
{
	if (rec == 0) {
		return addition(m);
	}
	addition_rec(m, rec - 1);
}

int
main(int c, char *v[])
{
	mtype_t m = {
		.m_x = 30,
		.m_long = 10,
	};
	return addition_rec(m, 5);
}

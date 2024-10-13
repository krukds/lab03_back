def linear_congruential_generator(m, a, c, x0, amount):
    random_numbers = []
    Xn = x0
    random_numbers.append(Xn)

    for _ in range(1, amount):
        Xn1 = (a * Xn + c) % m
        random_numbers.append(Xn1)
        Xn = Xn1

    return random_numbers
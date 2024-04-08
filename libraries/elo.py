# Calculate expected score of players based on their elo ratings

class Elo:
    # Function to calculate the updated Elo ratings
    def expectedScore(self, player1, player2, result):
        # Validation
        if not isinstance(player1, int) or not isinstance(player2, int) or not isinstance(result, int) or result not in [0, 1]:
            return None

        # Options for result
        win = 1
        draw = 0.5
        lose = 0

        # K-coefficient
        k = 20

        # Expected scores
        ex1 = 1 / (1 + 10 ** ((player2 - player1) / 400))
        ex2 = 1 / (1 + 10 ** ((player1 - player2) / 400))

        # Calculate updated ratings based on the result
        if result == 1:  # Player 1 wins
            new_player1_rating = player1 + k * (win - ex1)
            new_player2_rating = player2 + k * (lose - ex2)
        elif result == 0:  # Player 1 loses
            new_player1_rating = player1 + k * (lose - ex1)
            new_player2_rating = player2 + k * (win - ex2)
        else:  # Draw
            new_player1_rating = player1 + k * (draw - ex1)
            new_player2_rating = player2 + k * (draw - ex2)

        return round(new_player1_rating, 0), round(new_player2_rating, 0)


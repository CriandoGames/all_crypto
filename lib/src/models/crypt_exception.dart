/// Exceção lançada quando a autenticação falha durante a decriptação.
///
/// Isso indica que os dados foram corrompidos ou adulterados, ou que
/// a chave/nonce fornecidos estão incorretos.
class CryptException implements Exception {
  /// Descrição da falha criptográfica.
  final String message;

  /// Cria uma exceção com uma [message] opcional.
  const CryptException([this.message = 'Autenticação falhou.']);

  @override
  String toString() => 'CryptException: $message';
}
